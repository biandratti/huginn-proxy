use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use aya::programs::links::{FdLink, LinkError, PinnedLink};
use aya::programs::tc::qdisc_add_clsact;
use aya::programs::tc::{NlOptions, SchedClassifierLinkId, TcAttachOptions};
use aya::programs::xdp::XdpLinkId;
use aya::programs::{LinkOrder, SchedClassifier, TcAttachType, Xdp, XdpMode};
use aya::sys::SyscallError;
use aya::util::KernelVersion;
use aya::Ebpf;
use huginn_ebpf_common::constants::{TC_SYN_PROGRAM, XDP_SYN_PROGRAM};
use tracing::{info, warn};

use crate::CaptureMode;
use crate::EbpfError;
use crate::XdpAttachMode;

pub(super) struct AttachOutcome {
    pub mode: CaptureMode,
    pub link_pinned: bool,
}

pub(super) fn attach_xdp(
    ebpf: &mut Ebpf,
    interface: &str,
    xdp_mode: XdpAttachMode,
    link_pin_path: &Path,
) -> Result<AttachOutcome, EbpfError> {
    let program: &mut Xdp = ebpf
        .program_mut(XDP_SYN_PROGRAM)
        .ok_or(EbpfError::ProgramNotFound)?
        .try_into()
        .map_err(EbpfError::ProgramType)?;

    program.load().map_err(EbpfError::ProgramLoad)?;

    let aya_mode = match xdp_mode {
        XdpAttachMode::Skb => XdpMode::Skb,
        XdpAttachMode::Native => XdpMode::Driver,
    };
    let mode = CaptureMode::from_xdp(xdp_mode);
    info!(interface, capture_mode = mode.as_str(), "eBPF XDP attaching");

    let (already_pinned, link_id) = match adopt_pinned_link(link_pin_path)? {
        Some(link) => (true, program.attach_to_link(link).map_err(EbpfError::Attach)?),
        None => (
            false,
            program
                .attach(interface, aya_mode)
                .map_err(EbpfError::Attach)?,
        ),
    };

    let link_pinned =
        persist_xdp_link(program, link_id, link_pin_path, already_pinned, interface, aya_mode)?;
    if !link_pinned {
        warn!(
            interface,
            capture_mode = mode.as_str(),
            "XDP attach did not produce a pinnable bpf_link (netlink fallback); agent restart will detach capture"
        );
    }

    Ok(AttachOutcome { mode, link_pinned })
}

// clsact qdisc must exist; EEXIST from a prior run is ignored.
pub(super) fn attach_tc(
    ebpf: &mut Ebpf,
    interface: &str,
    link_pin_path: &Path,
) -> Result<AttachOutcome, EbpfError> {
    if let Err(e) = qdisc_add_clsact(interface) {
        warn!(interface, error = %e, "clsact qdisc add returned an error (continuing; likely already present)");
    }

    let program: &mut SchedClassifier = ebpf
        .program_mut(TC_SYN_PROGRAM)
        .ok_or(EbpfError::ProgramNotFound)?
        .try_into()
        .map_err(EbpfError::ProgramType)?;

    program.load().map_err(EbpfError::ProgramLoad)?;

    let use_tcx = kernel_at_least(6, 6, 0);
    if !use_tcx {
        warn!(
            interface,
            "kernel is below 6.6 or version could not be read; attaching TC via netlink (no pinned link, agent restart will detach capture)"
        );
    }

    let mode = if use_tcx {
        CaptureMode::Tcx
    } else {
        CaptureMode::Netlink
    };
    info!(interface, capture_mode = mode.as_str(), "eBPF TC clsact ingress attaching");

    if use_tcx {
        let (already_pinned, link_id) = match adopt_pinned_link(link_pin_path)? {
            Some(link) => (true, program.attach_to_link(link).map_err(EbpfError::Attach)?),
            None => {
                let link_id = program
                    .attach_with_options(
                        interface,
                        TcAttachType::Ingress,
                        TcAttachOptions::TcxOrder(LinkOrder::default()),
                    )
                    .map_err(EbpfError::Attach)?;
                (false, link_id)
            }
        };
        persist_tc_link(program, link_id, link_pin_path, already_pinned)?;
        Ok(AttachOutcome { mode, link_pinned: true })
    } else {
        program
            .attach_with_options(
                interface,
                TcAttachType::Ingress,
                TcAttachOptions::Netlink(NlOptions::default()),
            )
            .map_err(EbpfError::Attach)?;
        Ok(AttachOutcome { mode, link_pinned: false })
    }
}

fn kernel_at_least(major: u8, minor: u8, patch: u16) -> bool {
    match KernelVersion::current() {
        Ok(current) => current >= KernelVersion::new(major, minor, patch),
        Err(error) => {
            warn!(
                error = %error,
                major,
                minor,
                patch,
                "could not read kernel version; treating as older than requested"
            );
            false
        }
    }
}

fn link_pin_missing(err: &LinkError) -> bool {
    match err {
        LinkError::SyscallError(SyscallError { io_error, .. }) => {
            io_error.kind() == std::io::ErrorKind::NotFound || io_error.raw_os_error() == Some(2)
        }
        _ => false,
    }
}

fn open_pinned_fd_link(path: &Path) -> Result<Option<PinnedLink>, EbpfError> {
    match PinnedLink::from_pin(path) {
        Ok(link) => Ok(Some(link)),
        Err(err) if link_pin_missing(&err) => Ok(None),
        Err(err) => Err(EbpfError::Link(err)),
    }
}

/// Open the pinned capture link if it is valid for this program type.
///
/// `InvalidLink` is a stale pin (wrong kind, leftover file). Unlink it and attach fresh rather
/// than failing agent start. `TryFrom<FdLink>` drops the fd on failure, so the pin must go too
/// or the next `pin()` hits EEXIST.
fn adopt_pinned_link<L>(path: &Path) -> Result<Option<L>, EbpfError>
where
    L: TryFrom<FdLink, Error = LinkError>,
{
    let Some(old) = open_pinned_fd_link(path)? else {
        return Ok(None);
    };
    match L::try_from(FdLink::from(old)) {
        Ok(link) => Ok(Some(link)),
        Err(LinkError::InvalidLink) => {
            warn!(
                path = %path.display(),
                "stale capture link pin; removing and attaching fresh"
            );
            if let Err(error) = std::fs::remove_file(path) {
                warn!(path = %path.display(), %error, "failed to remove stale capture link pin");
            }
            Ok(None)
        }
        Err(err) => Err(EbpfError::Link(err)),
    }
}

fn persist_tc_link(
    program: &mut SchedClassifier,
    link_id: SchedClassifierLinkId,
    pin_path: &Path,
    already_pinned: bool,
) -> Result<(), EbpfError> {
    let link = program.take_link(link_id).map_err(EbpfError::Attach)?;
    let fd_link: FdLink = link.try_into()?;
    if already_pinned {
        return Ok(());
    }
    pin_fd_link(fd_link, pin_path)
}

fn persist_xdp_link(
    program: &mut Xdp,
    link_id: XdpLinkId,
    pin_path: &Path,
    already_pinned: bool,
    interface: &str,
    aya_mode: XdpMode,
) -> Result<bool, EbpfError> {
    let link = program.take_link(link_id).map_err(EbpfError::Attach)?;
    match FdLink::try_from(link) {
        Ok(fd_link) => {
            if !already_pinned {
                pin_fd_link(fd_link, pin_path)?;
            }
            Ok(true)
        }
        Err(LinkError::InvalidLink) if already_pinned => {
            Err(EbpfError::Link(LinkError::InvalidLink))
        }
        Err(LinkError::InvalidLink) => {
            // take_link dropped the netlink link, which detaches. Re-attach and leave
            // the link owned by the program so drop(probe) still detaches on shutdown.
            warn!("XDP bpf_link is unavailable; re-attaching via netlink without pinning");
            program
                .attach(interface, aya_mode)
                .map_err(EbpfError::Attach)?;
            Ok(false)
        }
        Err(err) => Err(EbpfError::Link(err)),
    }
}

fn pin_fd_link(fd_link: FdLink, pin_path: &Path) -> Result<(), EbpfError> {
    fd_link
        .pin(pin_path)
        .map_err(|source| EbpfError::LinkPin { path: pin_path.display().to_string(), source })?;
    let _ = std::fs::set_permissions(pin_path, std::fs::Permissions::from_mode(0o666));
    Ok(())
}

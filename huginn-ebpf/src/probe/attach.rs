use aya::programs::{tc, SchedClassifier, TcAttachType, Xdp, XdpMode};
use aya::Ebpf;
use huginn_ebpf_common::constants::{TC_SYN_PROGRAM, XDP_SYN_PROGRAM};
use tracing::{info, warn};

use crate::CaptureBackend;
use crate::EbpfError;
use crate::XdpAttachMode;

pub(super) fn attach_xdp(
    ebpf: &mut Ebpf,
    interface: &str,
    xdp_mode: XdpAttachMode,
) -> Result<&'static str, EbpfError> {
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
    let mode_str = CaptureBackend::Xdp(xdp_mode).as_str();
    info!(interface, mode = mode_str, "eBPF XDP attaching");
    program
        .attach(interface, aya_mode)
        .map_err(EbpfError::Attach)?;
    Ok(mode_str)
}

// clsact qdisc must exist; EEXIST from a prior run is ignored.
pub(super) fn attach_tc(ebpf: &mut Ebpf, interface: &str) -> Result<&'static str, EbpfError> {
    if let Err(e) = tc::qdisc_add_clsact(interface) {
        warn!(interface, error = %e, "clsact qdisc add returned an error (continuing; likely already present)");
    }

    let program: &mut SchedClassifier = ebpf
        .program_mut(TC_SYN_PROGRAM)
        .ok_or(EbpfError::ProgramNotFound)?
        .try_into()
        .map_err(EbpfError::ProgramType)?;

    program.load().map_err(EbpfError::ProgramLoad)?;

    let mode_str = CaptureBackend::Tc.as_str();
    info!(interface, mode = mode_str, "eBPF TC clsact ingress attaching");
    program
        .attach(interface, TcAttachType::Ingress)
        .map_err(EbpfError::Attach)?;
    Ok(mode_str)
}

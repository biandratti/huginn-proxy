use huginn_net_tcp::tcp::{IpVersion, TcpOption, WindowSize};
use huginn_net_tcp::{ttl, window_size};

/// Raw TCP SYN data as extracted by the eBPF XDP program.
///
/// This is a transport type: `huginn-proxy-ebpf` populates it from the BPF map,
/// and this module consumes it to produce a `SynFingerprint`.
///
/// All network-byte-order fields (`window`, `src_port`) must be converted before use.
#[derive(Debug, Clone)]
pub struct TcpSynData {
    /// TCP window size (network byte order — convert with u16::from_be)
    pub window: u16,
    /// IP TTL (host byte order)
    pub ip_ttl: u8,
    /// Length of valid bytes in `options` (host byte order)
    pub optlen: u16,
    /// Raw TCP options bytes (up to 40 bytes; only `optlen` bytes are valid)
    pub options: [u8; 40],
}

/// Result of parsing a TCP SYN fingerprint.
///
/// Contains the p0f-style raw signature extracted from the TCP SYN packet
/// via eBPF/XDP. OS matching against `huginn-net-db` is not included here —
/// that is a separate, future concern.
#[derive(Debug, Clone)]
pub struct SynFingerprint {
    /// p0f-style raw signature: `"ver:ittl:olen:mss:wsize,wscale:olayout"`
    ///
    /// Example: `"4:64:0:1460:8192,6:mss,nop,ws,nop,nop,ts,sok"`
    pub raw_signature: String,
}

/// Parse raw TCP SYN data from the eBPF map into a fingerprint.
///
/// Uses `huginn-net-tcp`'s TTL and window size functions plus an inline
/// TCP options parser (no `pnet` dependency here).
///
/// # Phase 1 note
/// `os_label` is always `None`. The inline `parse_options_raw` will be
/// moved to `huginn-net-tcp::parse_options_raw()` in Phase 2.
pub fn parse_syn_raw(data: &TcpSynData) -> Option<SynFingerprint> {
    // Convert window from network to host byte order
    let window_host = u16::from_be(data.window);

    // Parse TCP options from raw bytes (inline PoC parser — see Phase 2 notes)
    let valid_opts = &data.options[..data.optlen.min(40) as usize];
    let (olayout, mss, wscale) = parse_options_raw(valid_opts);

    // TTL: use huginn-net-tcp's calculate_ttl for p0f-style normalization
    let ittl = ttl::calculate_ttl(data.ip_ttl);

    // Window size: use huginn-net-tcp's detect_win_multiplicator
    let wsize: WindowSize = window_size::detect_win_multiplicator(
        window_host,
        mss.unwrap_or(0),
        20, // standard IPv4 header length
        olayout.contains(&TcpOption::TS),
        &IpVersion::V4,
    );

    let raw_signature =
        format_p0f_raw(data.ip_ttl, &ittl, mss, window_host, &wsize, wscale, &olayout);

    Some(SynFingerprint { raw_signature })
}

/// Inline TCP options parser for PoC.
///
/// Parses raw options bytes → (options list, MSS, window scale).
/// Uses the same algorithm as `huginn-net-tcp/src/tcp_process.rs::visit_tcp()`.
///
/// # Phase 2 migration
/// This function will be replaced by `huginn_net_tcp::parse_options_raw()`
/// once it is added to the library. The call site in `parse_syn_raw` will
/// become a one-line import change.
fn parse_options_raw(buf: &[u8]) -> (Vec<TcpOption>, Option<u16>, Option<u8>) {
    let mut olayout: Vec<TcpOption> = Vec::new();
    let mut mss: Option<u16> = None;
    let mut wscale: Option<u8> = None;
    let mut i = 0usize;

    while i < buf.len() {
        match buf[i] {
            0 => {
                // EOL — count remaining padding bytes after the EOL marker
                let remaining = buf.len().saturating_sub(i).saturating_sub(1);
                olayout.push(TcpOption::Eol(remaining as u8));
                break;
            }
            1 => {
                // NOP — single byte, no length field
                olayout.push(TcpOption::Nop);
                i = i.saturating_add(1);
            }
            kind => {
                // All other options: kind (1B) + length (1B) + data (length-2 B)
                let i_next = i.saturating_add(1);
                if i_next >= buf.len() {
                    break;
                }
                let len = buf[i_next] as usize;
                let i_end = i.saturating_add(len);
                if len < 2 || i_end > buf.len() {
                    break;
                }
                let data_start = i.saturating_add(2);
                let data = &buf[data_start..i_end];

                match kind {
                    2 => {
                        // MSS
                        olayout.push(TcpOption::Mss);
                        if data.len() >= 2 {
                            mss = Some(u16::from_be_bytes([data[0], data[1]]));
                        }
                    }
                    3 => {
                        // Window scale
                        olayout.push(TcpOption::Ws);
                        if !data.is_empty() {
                            wscale = Some(data[0]);
                        }
                    }
                    4 => olayout.push(TcpOption::Sok), // SACK permitted
                    5 => olayout.push(TcpOption::Sack), // SACK
                    8 => olayout.push(TcpOption::TS),  // Timestamps
                    n => olayout.push(TcpOption::Unknown(n)),
                }

                i = i_end;
            }
        }
    }

    (olayout, mss, wscale)
}

/// Format a p0f-style signature string from parsed SYN fields.
///
/// Format: `"ver:ittl:olen:mss:wsize,wscale:olayout"`
///
/// Example output: `"4:64:0:1460:8192,6:mss,nop,ws,nop,nop,ts,sok"`
fn format_p0f_raw(
    _raw_ttl: u8,
    ittl: &huginn_net_tcp::tcp::Ttl,
    mss: Option<u16>,
    window: u16,
    wsize: &WindowSize,
    wscale: Option<u8>,
    olayout: &[TcpOption],
) -> String {
    let ttl_str = match ittl {
        huginn_net_tcp::tcp::Ttl::Distance(base, _) => base.to_string(),
        huginn_net_tcp::tcp::Ttl::Value(v) => v.to_string(),
        huginn_net_tcp::tcp::Ttl::Guess(v) => v.to_string(),
        huginn_net_tcp::tcp::Ttl::Bad(v) => v.to_string(),
    };

    let mss_str = mss.map_or("*".to_string(), |m| m.to_string());

    let wsize_str = match wsize {
        WindowSize::Mss(mult) => format!("mss*{mult}"),
        WindowSize::Value(v) => v.to_string(),
        WindowSize::Mod(v) => format!("%{v}"),
        _ => window.to_string(),
    };

    let wscale_str = wscale.map_or("*".to_string(), |s| s.to_string());

    let opts_str = olayout
        .iter()
        .map(|o| match o {
            TcpOption::Eol(n) => format!("eol+{n}"),
            TcpOption::Nop => "nop".to_string(),
            TcpOption::Mss => "mss".to_string(),
            TcpOption::Ws => "ws".to_string(),
            TcpOption::Sok => "sok".to_string(),
            TcpOption::Sack => "sack".to_string(),
            TcpOption::TS => "ts".to_string(),
            TcpOption::Unknown(n) => format!("?{n}"),
        })
        .collect::<Vec<_>>()
        .join(",");

    // Format: ver:ittl:olen:mss:wsize,wscale:olayout
    // olen = 0 (IP options — not available from eBPF in Phase 1)
    format!("4:{ttl_str}:0:{mss_str}:{wsize_str},{wscale_str}:{opts_str}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_options() -> ([u8; 40], u16) {
        // Common Linux SYN options: MSS(1460), NOP, WS(6), NOP, NOP, TS, SOK
        // Meaningful bytes: 4+1+3+2+10+2 = 22 bytes; remaining 18 bytes are padding zeros.
        #[rustfmt::skip]
        let opts: [u8; 40] = [
            2, 4, 0x05, 0xb4,            // MSS = 1460
            1,                            // NOP
            3, 3, 6,                      // WS = 6
            1, 1,                         // NOP NOP
            8, 10, 0, 0, 0, 1, 0, 0, 0, 0, // Timestamps
            4, 2,                         // SACK permitted
            0, 0, 0, 0, 0, 0, 0, 0,      // padding (18 bytes)
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0,
        ];
        let optlen = 22u16;
        (opts, optlen)
    }

    #[test]
    fn test_parse_options_raw_extracts_mss() {
        let (opts, optlen) = make_test_options();
        let (_, mss, _) = parse_options_raw(&opts[..optlen as usize]);
        assert_eq!(mss, Some(1460));
    }

    #[test]
    fn test_parse_options_raw_extracts_wscale() {
        let (opts, optlen) = make_test_options();
        let (_, _, wscale) = parse_options_raw(&opts[..optlen as usize]);
        assert_eq!(wscale, Some(6));
    }

    #[test]
    fn test_parse_options_raw_olayout() {
        let (opts, optlen) = make_test_options();
        let (layout, _, _) = parse_options_raw(&opts[..optlen as usize]);
        assert!(layout.contains(&TcpOption::Mss));
        assert!(layout.contains(&TcpOption::Nop));
        assert!(layout.contains(&TcpOption::Ws));
        assert!(layout.contains(&TcpOption::TS));
        assert!(layout.contains(&TcpOption::Sok));
    }

    #[test]
    fn test_parse_syn_raw_produces_signature() {
        let (options, optlen) = make_test_options();
        let data = TcpSynData {
            window: 65535u16.to_be(), // network byte order
            ip_ttl: 64,
            optlen,
            options,
        };
        let Some(fp) = parse_syn_raw(&data) else {
            panic!("parse_syn_raw returned None for valid input");
        };
        assert!(!fp.raw_signature.is_empty());
        assert!(fp.raw_signature.starts_with("4:"));
    }

    #[test]
    fn test_empty_options() {
        let data =
            TcpSynData { window: 8192u16.to_be(), ip_ttl: 128, optlen: 0, options: [0u8; 40] };
        let fp = parse_syn_raw(&data);
        assert!(fp.is_some());
    }
}

use huginn_net_db::tcp::Quirk;

pub use huginn_proxy_ebpf_common::{quirk_bits, SynRawData};

/// Extension methods on [`SynRawData`] available on the userspace side.
///
/// Defined as a trait because `SynRawData` originates from the foreign crate
/// `huginn-proxy-ebpf-common` and Rust does not allow inherent impls on foreign types.
pub trait SynRawDataExt {
    fn decode_quirks(&self) -> Vec<Quirk>;
}

impl SynRawDataExt for SynRawData {
    fn decode_quirks(&self) -> Vec<Quirk> {
        let bits = self.quirks;
        let mut v = Vec::new();
        if bits & quirk_bits::DF != 0 {
            v.push(Quirk::Df);
        }
        if bits & quirk_bits::NONZERO_ID != 0 {
            v.push(Quirk::NonZeroID);
        }
        if bits & quirk_bits::ZERO_ID != 0 {
            v.push(Quirk::ZeroID);
        }
        if bits & quirk_bits::MUST_BE_ZERO != 0 {
            v.push(Quirk::MustBeZero);
        }
        if bits & quirk_bits::ECN != 0 {
            v.push(Quirk::Ecn);
        }
        if bits & quirk_bits::SEQ_ZERO != 0 {
            v.push(Quirk::SeqNumZero);
        }
        if bits & quirk_bits::ACK_NONZERO != 0 {
            v.push(Quirk::AckNumNonZero);
        }
        if bits & quirk_bits::NONZERO_URG != 0 {
            v.push(Quirk::NonZeroURG);
        }
        if bits & quirk_bits::URG != 0 {
            v.push(Quirk::Urg);
        }
        if bits & quirk_bits::PUSH != 0 {
            v.push(Quirk::Push);
        }
        v
    }
}

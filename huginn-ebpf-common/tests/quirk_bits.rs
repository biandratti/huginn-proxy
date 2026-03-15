//! Ensures values stay in sync with decode in huginn-ebpf (decode_quirks).

use huginn_ebpf_common::quirk_bits;

#[test]
fn quirk_bits_expected_values() {
    assert_eq!(quirk_bits::DF, 1 << 0);
    assert_eq!(quirk_bits::NONZERO_ID, 1 << 1);
    assert_eq!(quirk_bits::ZERO_ID, 1 << 2);
    assert_eq!(quirk_bits::MUST_BE_ZERO, 1 << 3);
    assert_eq!(quirk_bits::ECN, 1 << 4);
    assert_eq!(quirk_bits::SEQ_ZERO, 1 << 5);
    assert_eq!(quirk_bits::ACK_NONZERO, 1 << 6);
    assert_eq!(quirk_bits::NONZERO_URG, 1 << 7);
    assert_eq!(quirk_bits::URG, 1 << 8);
    assert_eq!(quirk_bits::PUSH, 1 << 9);
    assert_eq!(quirk_bits::NS, 1 << 10);
}

#[test]
fn quirk_bits_all_distinct() {
    let bits = [
        quirk_bits::DF,
        quirk_bits::NONZERO_ID,
        quirk_bits::ZERO_ID,
        quirk_bits::MUST_BE_ZERO,
        quirk_bits::ECN,
        quirk_bits::SEQ_ZERO,
        quirk_bits::ACK_NONZERO,
        quirk_bits::NONZERO_URG,
        quirk_bits::URG,
        quirk_bits::PUSH,
        quirk_bits::NS,
    ];
    for (i, &a) in bits.iter().enumerate() {
        for (j, &b) in bits.iter().enumerate() {
            if i != j {
                assert_eq!(a & b, 0, "quirk bits must not overlap: {a:#x} vs {b:#x}");
            }
        }
    }
}

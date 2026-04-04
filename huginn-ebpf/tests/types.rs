use huginn_ebpf::types::SynRawDataV4;

#[test]
fn test_syn_raw_data_size() {
    // 4 + 2 + 2 + 2 + 1 + 1 + 40 + 4 + 8 = 64 bytes
    assert_eq!(size_of::<SynRawDataV4>(), 64);
}

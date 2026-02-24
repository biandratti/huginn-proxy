use huginn_proxy_ebpf::types::SynRawData;

#[test]
fn test_syn_raw_data_size() {
    // 4 + 2 + 2 + 2 + 1 + 1 + 40 + 4 + 8 = 64 bytes
    assert_eq!(size_of::<SynRawData>(), 64);
}

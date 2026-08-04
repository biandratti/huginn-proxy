use huginn_ebpf::probe::random_seed;

#[test]
fn draws_a_seed_that_differs_between_loads() {
    let draw = || random_seed().unwrap_or_else(|e| panic!("could not draw a seed: {e}"));
    let a = draw();
    let b = draw();
    assert_ne!(a, b, "the seed must be redrawn per load, not a constant");
}

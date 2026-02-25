use std::path::PathBuf;
use std::process::Command;

/// Compile the BPF kernel program (`huginn-proxy-ebpf-xdp`) using
/// `cargo +nightly build` for the `bpfel-unknown-none` target.
///
/// The resulting ELF binary is embedded into the userspace binary via
/// `aya::include_bytes_aligned!` in `probe.rs`.
///
/// Requirements: Rust nightly toolchain with `rust-src` component.
/// The `rust-toolchain.toml` in `huginn-proxy-ebpf-xdp/` pins the channel.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let programs_dir = manifest_dir
        .parent()
        .ok_or("could not find workspace root")?
        .join("huginn-proxy-ebpf-xdp");

    println!("cargo:rerun-if-changed={}", programs_dir.join("src/main.rs").display());
    println!("cargo:rerun-if-changed={}", programs_dir.join("Cargo.toml").display());

    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);
    let bpf_target_dir = out_dir.join("bpf-programs-target");

    // When cargo runs a build script it sets several env vars pointing at the
    // current (stable) toolchain and compilation flags.  Those would be
    // inherited by the child cargo process and cause two classes of problems:
    //
    // 1. RUSTC / RUSTUP_TOOLCHAIN / RUSTC_WORKSPACE_WRAPPER / RUSTC_WRAPPER
    //    override the nightly selection we need; we remove them so rustup picks
    //    the toolchain from the rust-toolchain.toml inside huginn-proxy-ebpf-xdp/.
    //
    // 2. RUSTFLAGS / CARGO_ENCODED_RUSTFLAGS may carry coverage-instrumentation
    //    flags (e.g. `-C instrument-coverage`) injected by tarpaulin or other
    //    tools.  Those flags interact badly with `-Zbuild-std`: the instrumented
    //    core pulls fmt::Debug machinery into compiler_builtins, which the
    //    compiler then rejects with "cannot call functions through upstream
    //    monomorphizations" (rust-lang/rust#137222).  The BPF program must be
    //    compiled without any host-side instrumentation, so we strip these flags.
    let status = Command::new("cargo")
        .args(["build", "--release", "--package", "huginn-proxy-ebpf-xdp"])
        .env("CARGO_TARGET_DIR", &bpf_target_dir)
        .env_remove("RUSTC")
        .env_remove("RUSTDOC")
        .env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .current_dir(&programs_dir)
        .status();

    match status {
        Ok(s) if s.success() => {}
        Ok(s) => {
            return Err(format!(
                "cargo build of huginn-proxy-ebpf-xdp failed (exit {:?}).\n\
                Ensure nightly toolchain and rust-src are installed:\n\
                  rustup toolchain install nightly\n\
                  rustup component add rust-src --toolchain nightly",
                s.code()
            )
            .into());
        }
        Err(e) => {
            return Err(format!("failed to run cargo: {e}").into());
        }
    }

    // The compiled BPF ELF binary location
    let bpf_bin = bpf_target_dir.join("bpfel-unknown-none/release/huginn-proxy-ebpf-xdp");

    if !bpf_bin.exists() {
        return Err(format!("BPF binary not found at {}", bpf_bin.display()).into());
    }

    // Copy to OUT_DIR with the name probe.rs expects via XDP_BPF_OBJ
    let out_file = out_dir.join("xdp.bpf.o");
    std::fs::copy(&bpf_bin, &out_file)?;

    println!("cargo:rustc-env=XDP_BPF_OBJ={}", out_file.display());
    Ok(())
}

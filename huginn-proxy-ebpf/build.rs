use std::path::PathBuf;
use std::process::Command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=bpf/xdp.c");
    println!("cargo:rerun-if-changed=bpf/headers/bpf_helpers.h");
    println!("cargo:rerun-if-changed=bpf/headers/bpf_endian.h");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);
    let out_file = out_dir.join("xdp.bpf.o");

    let bpf_src = PathBuf::from("bpf/xdp.c");
    let bpf_headers = PathBuf::from("bpf/headers");

    // On Debian/Ubuntu (multiarch), arch-specific headers live under
    // /usr/include/<triple>/ (e.g. /usr/include/x86_64-linux-gnu/).
    // clang with `-target bpf` doesn't automatically add this path, so we
    // probe common locations and add whichever exists.
    let multiarch_include = detect_multiarch_include();

    let bpf_headers_str = bpf_headers
        .to_str()
        .ok_or("bpf/headers path contains non-UTF-8 characters")?;
    let bpf_src_str = bpf_src
        .to_str()
        .ok_or("bpf/xdp.c path contains non-UTF-8 characters")?;
    let out_file_str = out_file
        .to_str()
        .ok_or("OUT_DIR path contains non-UTF-8 characters")?;

    let mut args: Vec<&str> = vec![
        "-O2",
        "-g",
        "-Wall",
        "-target",
        "bpf",
        // Bundled BPF helper headers (bpf_helpers.h, bpf_endian.h, etc.)
        "-I",
        bpf_headers_str,
        // Standard Linux UAPI headers
        "-I",
        "/usr/include",
    ];

    if let Some(ref path) = multiarch_include {
        args.push("-I");
        args.push(path.as_str());
    }

    args.extend(["-c", bpf_src_str, "-o", out_file_str]);

    let status = Command::new("clang").args(&args).status();

    match status {
        Ok(s) if s.success() => {
            println!("cargo:rustc-env=XDP_BPF_OBJ={}", out_file.display());
        }
        Ok(s) => {
            return Err(format!(
                "clang failed with exit code {:?}. \
                Ensure clang and linux-headers-$(uname -r) are installed:\n  \
                sudo apt install clang linux-headers-$(uname -r)",
                s.code()
            )
            .into());
        }
        Err(e) => {
            return Err(format!(
                "Failed to run clang: {e}. Install it with: sudo apt install clang"
            )
            .into());
        }
    }

    Ok(())
}

/// Detect the multiarch include directory for the current host.
///
/// On Debian/Ubuntu with multiarch, arch-specific headers such as `asm/types.h`
/// are located under `/usr/include/<triple>/` (e.g. `/usr/include/x86_64-linux-gnu/`).
/// clang's BPF target does not add this automatically, causing "file not found" errors.
///
/// We first try `dpkg-architecture` for accuracy, then fall back to probing
/// known paths for common architectures.
fn detect_multiarch_include() -> Option<String> {
    // Try dpkg-architecture (Debian/Ubuntu)
    if let Ok(out) = Command::new("dpkg-architecture")
        .arg("-qDEB_HOST_MULTIARCH")
        .output()
    {
        if out.status.success() {
            if let Ok(triple) = std::str::from_utf8(&out.stdout) {
                let triple = triple.trim();
                let candidate = format!("/usr/include/{triple}");
                if std::path::Path::new(&candidate).exists() {
                    return Some(candidate);
                }
            }
        }
    }

    // Fallback: probe known multiarch paths for common architectures
    let candidates = [
        "/usr/include/x86_64-linux-gnu",
        "/usr/include/aarch64-linux-gnu",
        "/usr/include/arm-linux-gnueabihf",
        "/usr/include/riscv64-linux-gnu",
    ];
    candidates
        .iter()
        .find(|p| std::path::Path::new(p).exists())
        .map(|p| (*p).to_string())
}

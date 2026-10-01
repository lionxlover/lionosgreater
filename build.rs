// build.rs — link libpam without requiring libpam-dev.
//
// `pam-sys`/`bindgen` (used transitively by `pam-client`) fails to build
// without libclang. By vendoring our own FFI in `src/pam_ffi.rs` we drop
// that dependency entirely. We still need to tell the linker where to
// find libpam: prefer the unversioned `libpam.so` symlink shipped by
// libpam-dev, but fall back to the runtime-only `libpam.so.0` shipped
// by libpam0g — which is installed on every Linux box that has PAM at
// all (i.e. all of them).

use std::path::PathBuf;

fn main() {
    // The unversioned symlink normally lives in:
    //   /usr/lib/x86_64-linux-gnu/libpam.so          (Debian)
    //   /usr/lib64/libpam.so                          (Fedora)
    //   /usr/lib/libpam.so                            (Arch)
    // Look for it; if found, the default `-lpam` resolves. If not, fall
    // back to `-l:libpam.so.0` which finds the versioned runtime lib.

    let candidates: Vec<PathBuf> = common_lib_dirs()
        .iter()
        .map(|d| PathBuf::from(d).join("libpam.so"))
        .collect();

    if candidates.iter().any(|p| p.exists()) {
        // `-lpam` finds libpam.so in the standard search path.
        println!("cargo:rustc-link-lib=dylib=pam");
    } else {
        // GNU ld `:` syntax: link to a file named exactly `libpam.so.0`.
        println!("cargo:rustc-link-arg=-l:libpam.so.0");
    }

    println!("cargo:rerun-if-changed=build.rs");
}

fn common_lib_dirs() -> &'static [&'static str] {
    // Multi-arch layout for the major distros; harmless if some don't
    // exist — `Path::exists()` will just return false.
    &[
        "/usr/lib",
        "/usr/lib64",
        "/usr/lib/x86_64-linux-gnu",
        "/usr/lib/aarch64-linux-gnu",
        "/lib",
        "/lib64",
        "/lib/x86_64-linux-gnu",
        "/lib/aarch64-linux-gnu",
    ]
}

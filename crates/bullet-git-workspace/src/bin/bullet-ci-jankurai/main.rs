//! Local CI artifact admission only; no release or product authority.
//! The canonical dispatcher remains on its existing implementation until
//! this Rust replacement and its consumer composition are accepted.

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod tool;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn main() {
    std::process::exit(tool::entry(std::env::args_os().skip(1).collect()));
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() {
    eprintln!("jankurai-tool: UNSUPPORTED_LOCAL_TOOL_PROFILE");
    std::process::exit(75);
}

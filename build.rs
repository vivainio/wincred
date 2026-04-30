fn main() {
    // Use VERSION env var if set (from CI release tag), otherwise fall back to
    // CARGO_PKG_VERSION. The Cargo.toml version stays at 0.0.0 — the release
    // tag is the single source of truth.
    let version = std::env::var("VERSION")
        .map(|v| v.trim_start_matches('v').to_string())
        .unwrap_or_else(|_| env!("CARGO_PKG_VERSION").to_string());

    println!("cargo:rustc-env=BUILD_VERSION={version}");
    println!("cargo:rerun-if-env-changed=VERSION");
}

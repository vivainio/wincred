fn main() {
    // Use VERSION env var if set (from CI release tag), otherwise fall back to
    // CARGO_PKG_VERSION. The Cargo.toml version stays at 0.0.0 — the release
    // tag is the single source of truth.
    let version = std::env::var("VERSION")
        .map(|v| v.trim_start_matches('v').to_string())
        .unwrap_or_else(|_| env!("CARGO_PKG_VERSION").to_string());

    println!("cargo:rustc-env=BUILD_VERSION={version}");
    println!("cargo:rerun-if-env-changed=VERSION");
    println!("cargo:rerun-if-changed=build.rs");

    // Embed publisher metadata (right-click -> Properties -> Details) in the
    // Windows executable. Decided by the target, not the host, so
    // cross-compiling from Linux works too.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let mut res = winresource::WindowsResource::new();
    res.set("CompanyName", "Ville Vainio");
    res.set("ProductName", "wincred");
    res.set(
        "FileDescription",
        "wincred - Windows Credential Manager CLI (WSL-friendly)",
    );
    res.set("LegalCopyright", "Copyright \u{a9} 2026 Ville Vainio");
    res.set("OriginalFilename", "wincred.exe");

    // Stamp the release-tag version instead of the 0.0.0 placeholder.
    res.set("FileVersion", &version);
    res.set("ProductVersion", &version);
    let mut parts = version
        .split(|c: char| !c.is_ascii_digit())
        .map(|p| p.parse::<u64>().unwrap_or(0));
    let mut next = || parts.next().unwrap_or(0) & 0xffff;
    let packed = (next() << 48) | (next() << 32) | (next() << 16) | next();
    res.set_version_info(winresource::VersionInfo::FILEVERSION, packed);
    res.set_version_info(winresource::VersionInfo::PRODUCTVERSION, packed);

    if let Err(e) = res.compile() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

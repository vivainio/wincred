use clap::{Parser, Subcommand};
use serde::Serialize;
use std::io::{self, Read};
use std::process::ExitCode;

#[derive(Parser)]
#[command(version = env!("BUILD_VERSION"), about = "Windows Credential Manager CLI (WSL-friendly)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,

    /// Emit JSON instead of plain text
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print the secret for <target> to stdout
    Get { target: String },
    /// Store a credential; secret is read from stdin
    Set {
        target: String,
        #[arg(long, default_value = "")]
        user: String,
    },
    /// Delete a credential
    Delete { target: String },
    /// List credentials, optionally filtered by prefix
    List {
        #[arg(long)]
        prefix: Option<String>,
    },
}

#[derive(Serialize)]
struct CredOut {
    target: String,
    username: String,
    secret: Option<String>,
}

#[derive(Serialize)]
struct ListEntry {
    target: String,
    username: String,
}

const EXIT_OK: u8 = 0;
const EXIT_NOT_FOUND: u8 = 1;
// 2 is reserved for clap's own usage-error exits.
const EXIT_OS: u8 = 3;

fn main() -> ExitCode {
    let cli = Cli::parse();
    #[cfg(windows)]
    {
        unsafe {
            use windows::Win32::System::Console::SetConsoleOutputCP;
            let _ = SetConsoleOutputCP(65001);
        }
        match run(cli) {
            Ok(code) => ExitCode::from(code),
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(EXIT_OS)
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = cli;
        eprintln!("wincred only runs on Windows; invoke wincred.exe from WSL");
        ExitCode::from(EXIT_OS)
    }
}

#[cfg(windows)]
fn run(cli: Cli) -> windows::core::Result<u8> {
    match cli.cmd {
        Cmd::Get { target } => get(&target, cli.json),
        Cmd::Set { target, user } => set(&target, &user),
        Cmd::Delete { target } => delete(&target),
        Cmd::List { prefix } => list(prefix.as_deref(), cli.json),
    }
}

#[cfg(windows)]
fn to_pcwstr(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn from_pwstr(p: windows::core::PWSTR) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe { p.to_string().unwrap_or_default() }
}

#[cfg(windows)]
fn strip_legacy_prefix(s: String) -> String {
    s.strip_prefix("LegacyGeneric:target=")
        .map(str::to_owned)
        .unwrap_or(s)
}

#[cfg(windows)]
fn get(target: &str, json: bool) -> windows::core::Result<u8> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::ERROR_NOT_FOUND;
    use windows::Win32::Security::Credentials::{CredFree, CredReadW, CREDENTIALW, CRED_TYPE_GENERIC};

    let w = to_pcwstr(target);
    let mut p: *mut CREDENTIALW = std::ptr::null_mut();
    let res = unsafe { CredReadW(PCWSTR(w.as_ptr()), CRED_TYPE_GENERIC, 0, &mut p) };
    if let Err(e) = res {
        if e.code() == ERROR_NOT_FOUND.to_hresult() {
            return Ok(EXIT_NOT_FOUND);
        }
        return Err(e);
    }

    let cred = unsafe { &*p };
    let blob =
        unsafe { std::slice::from_raw_parts(cred.CredentialBlob, cred.CredentialBlobSize as usize) };
    let secret = decode_blob(blob);
    let username = from_pwstr(cred.UserName);
    let target_out = strip_legacy_prefix(from_pwstr(cred.TargetName));

    if json {
        let out = CredOut {
            target: target_out,
            username,
            secret: Some(secret),
        };
        println!("{}", serde_json::to_string(&out).unwrap());
    } else {
        print!("{secret}");
    }

    unsafe { CredFree(p as *const _) };
    Ok(EXIT_OK)
}

#[cfg(windows)]
fn decode_blob(blob: &[u8]) -> String {
    if blob.len() >= 2 && blob.len() % 2 == 0 {
        let u16s: Vec<u16> = blob
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        if let Ok(s) = String::from_utf16(&u16s) {
            if !s.contains('\0') {
                return s;
            }
        }
    }
    String::from_utf8_lossy(blob).into_owned()
}

#[cfg(windows)]
fn set(target: &str, user: &str) -> windows::core::Result<u8> {
    use windows::core::PWSTR;
    use windows::Win32::Security::Credentials::{
        CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC,
    };

    let mut secret = String::new();
    io::stdin()
        .read_to_string(&mut secret)
        .map_err(|e| windows::core::Error::new(windows::core::HRESULT(-1), format!("{e}")))?;
    if secret.ends_with('\n') {
        secret.pop();
        if secret.ends_with('\r') {
            secret.pop();
        }
    }

    let mut target_w = to_pcwstr(target);
    let mut user_w = to_pcwstr(user);
    let blob: Vec<u8> = secret.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();

    let cred = CREDENTIALW {
        Flags: Default::default(),
        Type: CRED_TYPE_GENERIC,
        TargetName: PWSTR(target_w.as_mut_ptr()),
        Comment: PWSTR::null(),
        LastWritten: Default::default(),
        CredentialBlobSize: blob.len() as u32,
        CredentialBlob: blob.as_ptr() as *mut u8,
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        AttributeCount: 0,
        Attributes: std::ptr::null_mut(),
        TargetAlias: PWSTR::null(),
        UserName: PWSTR(user_w.as_mut_ptr()),
    };

    unsafe { CredWriteW(&cred, 0)? };
    Ok(EXIT_OK)
}

#[cfg(windows)]
fn delete(target: &str) -> windows::core::Result<u8> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::ERROR_NOT_FOUND;
    use windows::Win32::Security::Credentials::{CredDeleteW, CRED_TYPE_GENERIC};

    let w = to_pcwstr(target);
    match unsafe { CredDeleteW(PCWSTR(w.as_ptr()), CRED_TYPE_GENERIC, 0) } {
        Ok(()) => Ok(EXIT_OK),
        Err(e) if e.code() == ERROR_NOT_FOUND.to_hresult() => Ok(EXIT_NOT_FOUND),
        Err(e) => Err(e),
    }
}

#[cfg(windows)]
fn list(prefix: Option<&str>, json: bool) -> windows::core::Result<u8> {
    use windows::core::PCWSTR;
    use windows::Win32::Security::Credentials::{
        CredEnumerateW, CredFree, CREDENTIALW, CRED_ENUMERATE_ALL_CREDENTIALS,
    };

    let filter_w: Option<Vec<u16>> = prefix.map(|p| to_pcwstr(&format!("{p}*")));
    let filter_ptr = match &filter_w {
        Some(v) => PCWSTR(v.as_ptr()),
        None => PCWSTR::null(),
    };
    let flags = if filter_w.is_none() {
        CRED_ENUMERATE_ALL_CREDENTIALS
    } else {
        Default::default()
    };

    let mut count: u32 = 0;
    let mut creds: *mut *mut CREDENTIALW = std::ptr::null_mut();
    unsafe { CredEnumerateW(filter_ptr, flags, &mut count, &mut creds)? };

    let mut entries = Vec::with_capacity(count as usize);
    for i in 0..count as isize {
        let c = unsafe { &**creds.offset(i) };
        if c.Type != windows::Win32::Security::Credentials::CRED_TYPE_GENERIC {
            continue;
        }
        entries.push(ListEntry {
            target: strip_legacy_prefix(from_pwstr(c.TargetName)),
            username: from_pwstr(c.UserName),
        });
    }
    unsafe { CredFree(creds as *const _) };

    if json {
        println!("{}", serde_json::to_string(&entries).unwrap());
    } else {
        for e in entries {
            if e.username.is_empty() {
                println!("{}", e.target);
            } else {
                println!("{}\t{}", e.target, e.username);
            }
        }
    }
    Ok(EXIT_OK)
}

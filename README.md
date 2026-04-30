# wincred

A small CLI for the Windows Credential Manager, designed to be invoked from WSL.

## Why

WSL has no native access to the Windows credential store. `wincred.exe` is a tiny
Windows binary (under 500 KB) you can call from Linux side via WSL's Windows interop
to read, write, list, and delete generic credentials owned by the current Windows user.

## Install

Download `wincred.exe` from the [Releases](../../releases) page and put it on your
Windows `PATH`. From WSL, it's then directly callable as `wincred.exe`.

Or build from source:

```sh
cargo install --path .
```

## Usage

```
wincred get <target>              # print secret to stdout
wincred get <target> --json       # {"target":..,"username":..,"secret":..}
wincred set <target> [--user U]   # secret read from stdin
wincred delete <target>
wincred list [--prefix P] [--json]
```

Exit codes: `0` ok, `1` not found, `2` usage error, `3` OS error.

## Calling from WSL

```sh
TOKEN=$(wincred.exe get 'github:my-pat' | tr -d '\r')
```

Strip `\r` because Windows binaries emit CRLF line endings.

## Limitations

- Only handles `CRED_TYPE_GENERIC` credentials. Domain credentials are not exposed
  to user-mode reads by Windows.
- Credentials are scoped to the current Windows user.
- The secret crosses the WSL/Windows interop boundary in plaintext.

## License

MIT

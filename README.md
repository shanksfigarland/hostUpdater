# hostUpdater

Fast `/etc/hosts` synchronization for authorized lab networks using
[NetExec](https://github.com/Pennyw0rth/NetExec).

`hostUpdater` discovers hostnames, removes invalid mappings, shows the results,
and asks before updating `/etc/hosts`. Manual entries remain untouched.

This project was inspired by
[eMVee-NL/UpdateHostsFile](https://github.com/eMVee-NL/UpdateHostsFile), a
useful workflow for keeping `/etc/hosts` entries synchronized during OSEP lab
exercises. I wanted a standalone Go implementation with a simple interactive
experience and additional safeguards for repeated lab use.

`hostUpdater` extends that workflow with concurrent discovery, automatic subnet
detection, a dedicated managed block, backups, dry-run previews, and an undo
process that restores the original hosts file without discarding the latest
managed state.

## Features

- One-command interactive workflow
- Automatic lab subnet detection
- Concurrent NetExec scans with per-protocol timeouts
- SMB-only quick mode for larger networks
- LDAP hostname and domain enrichment
- Safe managed block inside `/etc/hosts`
- Backups, dry-run preview, and undo
- Optional temporary Kali lab-interface setup

## Requirements

- Linux on amd64 or arm64
- [NetExec](https://github.com/Pennyw0rth/NetExec) available as `nxc`
- Root privileges when writing `/etc/hosts` or configuring an interface

## Quick Start

Check your architecture:

```bash
uname -m
```

Download the matching binary:

| `uname -m` output | Binary |
| --- | --- |
| `x86_64` | `hostupdater-linux-amd64` |
| `aarch64` or `arm64` | `hostupdater-linux-arm64` |

Rename it for shorter commands:

```bash
mv hostupdater-linux-amd64 hostupdater
chmod +x hostupdater
sudo ./hostupdater scan
```

The default scan:

1. Detects your lab subnet or asks for one.
2. Runs supported NetExec protocols concurrently.
3. Displays valid hostnames and responding protocols.
4. Asks before updating `/etc/hosts`.

If Kali needs a temporary lab-interface address, enter a usable host address
such as `192.168.56.100/24`, not the subnet address `192.168.56.0/24`.

## Common Commands

```bash
# Preview without modifying /etc/hosts
sudo ./hostupdater scan --dry-run

# Scan a specific subnet
sudo ./hostupdater scan -t 192.168.56.0/24

# Faster SMB-only scan
sudo ./hostupdater scan --quick

# Restore the original hosts file
sudo ./hostupdater undo
```

Run `./hostupdater scan --help` for advanced options.

## Undo Changes

The first successful update saves your original hosts file as:

```text
/etc/hosts.hostupdater.original
```

Restore that original file at any time:

```bash
sudo ./hostupdater undo
```

Before restoring, `undo` creates a snapshot of the current file:

```text
/etc/hosts.before-undo.TIMESTAMP
```

This means you can safely return to the original `/etc/hosts` file without
losing the most recent managed version.

## Managed Block

Only the managed block is replaced. Existing manual entries are preserved.

```text
# BEGIN HOSTUPDATER MANAGED BLOCK
192.168.56.10   kingslanding.sevenkingdoms.local kingslanding # source=ldap
# END HOSTUPDATER MANAGED BLOCK
```

## Build

Build for your current system:

```bash
go test ./...
go build -trimpath -ldflags="-s -w" -o hostupdater .
```

Build Linux release binaries for amd64 and arm64 from Windows PowerShell:

```powershell
.\build-release.ps1
```

Release files are written to `dist/` with a `SHA256SUMS` file.

## Authorized Use

Use this tool only on networks you own or have explicit authorization to test.

## License

GPL-3.0. See [LICENSE](LICENSE).

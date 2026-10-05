# Testing

## Automated tests

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

They use temp dirs, fake roots, fake `sudo` scripts and the mock portal in `crates/testkit`; they never touch the real config, systemd, the user's notification service or a real portal. `crates/pithagoras-sync/tests/e2e.rs` runs the real binary against the mock portal, `tests/update.rs` runs the updater against releases in temp dirs and on a loopback HTTP server. The Windows tests run on a Windows machine with `scripts/windows-vm-test.sh <host>`.

## Tools for trying a real client by hand

Two programs in `crates/testkit` (built with `cargo build -p sync-testkit --bins`):

- `sync-mock-portal [port]`: the mock portal on loopback. It prints `portal http://127.0.0.1:<port>`, then reads one command per line from stdin (`code <CODE>`, `wait`, `exec <cwd> <command>`, `approve once|deny|none`, `call <method> <json>`, `read <path>`, `close`, `closed`, `sleep`, `grep <text>`, `dump <file>`, `quit`; the source lists them). To drive it from another shell, feed it a file: `tail -f mock.cmds | sync-mock-portal 18080`, then `echo 'code ABC123' >> mock.cmds`.
- `sync-test-sign keygen <keyfile>` writes a throwaway minisign key and prints its public key; `sync-test-sign sign <keyfile> <file>` writes `<file>.minisig` in minisign's format.

A build that can update itself needs a release key compiled in:

```sh
pub=$(sync-test-sign keygen test.key)
PITHAGORAS_SYNC_UPDATE_KEY="$pub" cargo build --release -p pithagoras-sync
```

`PITHAGORAS_SYNC_UPDATE_URL` sets the default manifest URL the same way; without it, `update --manifest <url or file>` names it. A release folder holds `manifest.json`:

```json
{"version": "0.1.1", "artifacts": {"x86_64-linux": {"url": "pithagoras-sync-x86_64", "size": 11206656, "sha256": "<hex>"}}}
```

next to `manifest.json.minisig` (`sync-test-sign sign test.key manifest.json`) and the binary. `url` is relative to the manifest or absolute.

## The test machine

A test container, Ubuntu 24.04 (Proxmox kernel 7.0, systemd 255; no Landlock in its LSM list, so Folders mode asks for every command there). The client, the mock portal and `sync-test-sign` were musl release builds copied to `/opt/pst`, built with `PITHAGORAS_SYNC_UPDATE_KEY` set to a throwaway test key; a second build with the version bumped to 0.1.1 served as the update. The mock portal ran on the container itself (port 18080), driven through a command file as above. Nothing here touched another machine or a real portal. Run on 2026-10-05, phase 1b.

### Dedicated user with a system unit

```sh
pithagoras-sync setup --create-user --yes
sudo -H -u pithagoras-sync pithagoras-sync pair '<uri from the mock>'
sudo -H -u pithagoras-sync pithagoras-sync folder add /srv/proj --rw --exec
sudo -H -u pithagoras-sync pithagoras-sync mode folders
systemctl start pithagoras-sync
```

- `setup` created the locked user `pithagoras-sync`, the program in `/usr/local/bin` and the system unit.
- `exec` in `/srv/proj` asked ("the kernel has no Landlock, so every command asks"); approved, it ran in its own cgroup, `/system.slice/pithagoras-sync.service/pithagoras-exec-<pid>-1`. A working folder outside the grant was denied.
- `panic` closed the link and killed a `setsid` child of a running command; `unlock` reconnected. The mock's `close` was followed by a reconnect.
- `policy.set` from the mock was `DENIED` under the default `portal_policy = read`.
- `mode full`: commands in `/tmp` ran without asking.
- `setup --remove --yes` removed the user and the unit; `/usr/local/bin/pithagoras-sync` stays, as documented.

### Elevation with real sudo

A user `elevtest` with a password containing a quote and a backslash, in sudoers with `ALL=(ALL:ALL) ALL`. Lingering was enabled by root (the user's own `loginctl enable-linger` was refused by polkit, and `install` printed the hint for it).

```sh
pithagoras-sync install                                  # user unit
pithagoras-sync pair '<uri>'
pithagoras-sync config set policy.privilege.elevation sudo
pithagoras-sync mode full
printf '%s\n' "$PW" | pithagoras-sync secret set elevation --stdin
```

Results, each command approved through the mock portal:

- `sudo id -u` printed `0`.
- As root, the elevated command wrote its environment, its stdin (0 bytes), `ps` output (35 lines), every `/proc/*/cmdline` and every `/proc/*/environ` to files: none contained the password. A root watcher reading `/proc/*/cmdline` and `environ` in a loop with `grep -F -f` during the run found nothing.
- `cat /root/pw.txt` (a file holding the password): permission denied. `sudo cat /root/pw.txt`: the output reached the portal as `[redacted]`.
- `sudo -u nobody id`: refused (sudo's own options are not taken).
- The client's `/proc/<pid>/environ` belongs to root:root (the client is undumpable), so the user's other processes cannot read its memory.
- With `strace` attached to the client: the exec shim refused to take the password (exit 126) and `secret set` was refused ("being traced").
- A wrong stored password: sudo answered "Sorry, try again" and "1 incorrect password attempt", exit 1.
- After `panic`, `secret status` said "no password set".
- The audit log, the user's journal, the full system journal and the mock portal's transcript of everything the device sent (`dump`) held the password neither as it is nor JSON-escaped.
- `secret_storage = file`: `~/.config/pithagoras-sync/elevation.secret` was 0600 and the password worked after a restart of the client. `fs.read` of the file was denied (sealed). An unconfined Full-mode `cat` of it was readable, its output `[redacted]`: the known limit of file storage. `secret clear` removed the file.

### Update

As `elevtest`, against a local release folder with 0.1.1:

- `update --check` reported 0.1.1.
- `update` replaced `~/.local/bin/pithagoras-sync`; the client exited with 75 and systemd started it again as 0.1.1. The config file was byte for byte the same (`cmp`).
- `update` again: "Up to date".
- A manifest changed after signing: refused, the signature does not verify, exit 1.

### Root

```sh
pithagoras-sync config set policy.privilege.allow_root true   # without it, install --system refuses
pithagoras-sync install --system
```

`id -u` through the portal printed `0`, the command ran in its own cgroup, `panic` killed a `setsid` child and `unlock` reconnected. The journal warns "running as root".

### Ask and the portal's write access

- With `policy.approvals.timeout_secs = 5` and no answer: "no answer to the approval within 5s", audited.
- With `portal_policy = write`: `policy.set` switched `policy.tools.bash` off, audited as `by the portal: true -> false`.

### Cleanup

The units were uninstalled, `elevtest` and its sudoers file removed, the mock stopped, and `/opt/pst`, root's test files and configs deleted.

## Windows

A Windows test VM (Windows 10.0.26300, Windows PowerShell 5.1, no `pwsh`, OpenSSH server, an administrator account, so every ssh session was elevated). Nothing was installed on it: no Rust, no build tools. Everything was cross-built on Linux with `cargo-xwin` and copied over. Run on 2026-10-05, phase 1.

### The test suite

```sh
scripts/windows-vm-test.sh <user>@<windows host>
```

It builds the client and every test program for `x86_64-pc-windows-msvc`, copies them to a fresh folder in the user's home, runs each there and removes the folder. All 19 test programs passed. The Windows-only ones:

- `crates/ops/tests/files_windows.rs`: a junction swapped in under a granted folder fails read, stat, write and list, and the file outside is not truncated; short names and case reach the same file.
- `crates/ops/tests/exec.rs`: PowerShell output is plain UTF-8 text (no CLIXML, no OEM code page), the command has no console window, the exit code arrives.
- `crates/pithagoras-sync/tests/e2e_windows.rs`: the real client against the mock portal: refused when elevated until `allow_root`, the control pipe's security, Folders mode prompting, the file tools, an unconfined shell, `panic` and a killed client both ending a `Start-Process` child, `unlock`.
- `crates/pithagoras-sync/tests/update_windows.rs`: a release from a `C:\` manifest path replaces a running program, which goes aside to `.old`.

Found this way and fixed: the program needed `VCRUNTIME140.dll`, which a fresh Windows lacks (it now links the C runtime statically, `.cargo/config.toml`; the script refuses a build that imports it); every config failed validation on Windows (`sudo_path` judged as a Windows path); a junction swapped in after the check could empty a file outside the folder; PowerShell errors arrived as CLIXML and non-ASCII output in code page 850; the protected-path check missed `\` and the PowerShell home variables; `update` looked for a local release's binary in the working directory.

### By hand, against the mock portal

The client ran with its own profile (`USERPROFILE`, `APPDATA` and `LOCALAPPDATA` pointed to a test folder), the mock portal ran on the Linux machine, and the VM reached it through `ssh -N -R 18080:127.0.0.1:18080 <vm>`, so the portal URL was `http://127.0.0.1:18080` there.

- Paths sent as the portal sends them: case-insensitive matches, an 8.3 name and `sub/../a.txt` inside the folder worked. `C:\`, `c:/`, `//localhost/c$`, `//?/C:`, `a.txt:hidden`, `a.txt::$DATA`, `CON`, `nul.txt` and a trailing dot were `BAD_PATH`; paths outside the folder, a junction and a symlink to outside were `DENIED`; a symlink to `\\localhost\c$` was `BAD_PATH`.
- Commands: Folders mode asked for each; approved, they ran. Timeout, `exec.signal`, the mock's `close` and `panic` each ended a hidden `Start-Process` child. The mock's `close` was followed by a reconnect within a second; `panic` closed the link with 1000 and `unlock` reconnected.
- A process started through WMI (`Win32_Process.Create`) survived `panic`: the job does not reach it.
- With `folders_shell = "unconfined"`, a command read `~\.ssh\id_ed25519` and wrote outside the folder once approved: Folders mode does not confine commands on Windows.
- The control pipe: before the fix, a Low-integrity copy of PowerShell (`icacls /setintegritylevel low`) could connect for reading and held every instance, so `panic` failed with "all pipe instances are busy". After it, that process was refused in every direction. A second Windows user was not available, so another account was not tried.

### Start at logon

`pithagoras-sync install` (the real task name, "Pithagoras Sync"; there was none before):

- The task was created and started; the client ran in the user's session (2), at Medium integrity, without a console window, and the CLI in the elevated ssh session reached it over the pipe.
- `install` again while it ran: it ended the task's client, replaced the program (the running copy went to `.old`) and started it again.
- Killed with `taskkill /f`, the client stayed down with Task Scheduler's restart on failure alone (more than 2 minutes); with the minute trigger it was back after 10 seconds.
- `uninstall` ended the client and deleted the task and its definition.
- Not tested: a real logoff and logon, since the VM offers no way to log on again without its password, and whether a console window flashes then.

### Cleanup

The task was deleted, the client stopped, and the test folders, the client's folders under `%APPDATA%` and `%LOCALAPPDATA%` and the installed program removed from the VM.

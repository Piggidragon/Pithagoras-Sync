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

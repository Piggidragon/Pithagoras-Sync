# Pithagoras Sync

The device client of Pithagoras Sync: one Rust binary, `pithagoras-sync`, that connects a computer to a Pithagoras portal so the portal's agent can use its files and shell. The design is issue #1 of `Piggidragon/Pithagoras-Sync` (the architecture document); the wire protocol is `docs/protocol.md`.

This file applies to every agent in this repo.

## Layout

- `crates/proto`: the wire protocol (JSON-RPC frames, binary frames, method params and results). Change it together with `docs/protocol.md`.
- `crates/policy`: modes, folders, protected paths, command patterns, taint, approvals and the audit log. Everything the device decides on its own.
- `crates/ops`: what a call does on the device (files, grep, find, exec with its isolation, probe, info).
- `crates/connector`: TLS and pinning, pairing, token storage, the WebSocket client and the dispatcher that runs every call through the policy.
- `crates/pithagoras-sync`: the binary: CLI, daemon, control socket, `install` and `setup`.
- `docs/windows.md`: what differs on Windows and what is unverified there.
- `crates/testkit`: the mock portal the tests talk to. The real portal side does not exist yet.

The cargo feature `overlay` (phase 2: GUI, audio, hotkeys, computer use) is off; phase 1 builds without it.

## Rules

- The device defends itself from the portal. A portal message may never widen the mode, folders, protections or expiry; unknown fields and methods are errors, not ignored.
- Fail closed: no notification service, a timeout or any doubt means deny.
- Every security rule has a test that fails without it. Check that by writing the old code back temporarily (save the file aside, `git show <rev>:<path> > <path>`, run, copy the new one back). Never `git stash`.
- Tests never touch the real `~/.config`, `~/.pi`, a real portal, the user's notification service or systemd. They use temp dirs, the mock portal, fake roots and fake command runners.
- Nothing may assume one owner's setup: hosts, IPs, user names, paths. Use neutral placeholders.

## Build and checks

The machine is short on memory and `/tmp` is a RAM tmpfs. Before a build check `free -m` (at least 6 GB available), then build under a cap with the target and temp dirs on disk:

```sh
export CARGO_TARGET_DIR=/var/tmp/<task>/target TMPDIR=/var/tmp/<task>/tmp CARGO_BUILD_JOBS=4
systemd-run --user --scope -p MemoryMax=6G -p MemorySwapMax=0 -- cargo test
```

All three must be clean before a commit:

- `cargo fmt --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test`

Release artefact: `CC_x86_64_unknown_linux_musl=clang cargo build --release --target x86_64-unknown-linux-musl -p pithagoras-sync` (ring needs a C compiler for musl; clang works, so does `musl-gcc`). Windows: `cargo xwin build --release --target x86_64-pc-windows-msvc -p pithagoras-sync`, and `cargo xwin clippy --workspace --target x86_64-pc-windows-msvc --all-targets -- -D warnings` must be clean too. The Windows tests run only on a Windows machine: `scripts/windows-vm-test.sh <host>`.

## Git

Same rules as the portal repo: commit with `git -c user.name=Piggidragon -c user.email=piggidragon.dev@proton.me commit`, English messages with a plain imperative subject and the trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. No stash, force-push, `reset --hard` or branch deletion; no new dependencies without asking.

# Pithagoras Sync

Lets the agent of your [Pithagoras](https://github.com/thecodacus/pithagoras) portal reach your own computers, the way a file-sync client reaches the cloud: pair once, it starts with the machine, reconnects by itself, and from then on the agent can use that computer's files, shell and git when a chat is granted the device.

**Status: phase 1 in progress, no portal yet.** The portal side (the `/sync/v1` hub, the Devices page, the tool wrapper) is not written, so this client cannot be used yet. It is tested against a mock portal only.

## Build

Needs Rust (stable, 1.85 or newer).

```sh
cargo build --release -p pithagoras-sync
```

## Test

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Licence

Apache-2.0, see [LICENSE](LICENSE).

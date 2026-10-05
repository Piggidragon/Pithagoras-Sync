# Releasing

A release is a version tag. `.github/workflows/release.yml` then checks the workspace (`cargo fmt --check`, clippy, the tests), builds the binaries, signs the update manifest and publishes a GitHub Release. `pithagoras-sync update` reads the manifest of the newest release (`releases/latest/download/manifest.json` of this repository: the stable channel; pre-releases are not "latest", so they never reach it).

## What a release holds

| File | What |
|---|---|
| `pithagoras-sync-x86_64-linux` | Static musl binary, x86_64 |
| `pithagoras-sync-aarch64-linux` | Static musl binary, aarch64 (built on GitHub's arm64 runner) |
| `pithagoras-sync-x86_64-windows.exe` | Windows x86_64, with the C runtime linked in |
| `manifest.json` | The version and, per target (`x86_64-linux`, `aarch64-linux`, `x86_64-windows`), each binary's URL, size and sha256 |
| `manifest.json.minisig` | The manifest's signature by the release key |
| `SHA256SUMS` | Checksums of everything above, for `sha256sum -c` |

Every binary has the release key's public half compiled in (`PITHAGORAS_SYNC_UPDATE_KEY`). The client takes a manifest only with a valid signature by that key, a binary only with the size and sha256 the manifest names, and only a newer version (protocol.md, decision 13).

## One-time setup

The release key is a minisign-compatible Ed25519 key. Its secret half lives only in a GitHub secret; its public half goes into every binary. Make it once, on a machine you trust, from a checkout of this repository:

```sh
cargo run --release -p sync-release -- keygen release.key
```

It writes the secret key to `release.key` (readable by you only; it never overwrites a file) and prints the public key, one line of base64 starting with `RW`. Then, in the repository's Settings, Secrets and variables, Actions:

1. **Variable** `PITHAGORAS_SYNC_UPDATE_KEY`: the public key line. A variable, not a secret: it is public, and every binary carries it.
2. **Secret** `PITHAGORAS_SYNC_SIGNING_KEY`: the whole content of `release.key`.

Keep `release.key` offline (a password manager or an encrypted backup) and delete the working copy. Never commit it, and never use it in tests: tests make throwaway keys.

Losing the secret key means the clients in the field cannot take another update: they trust only the key compiled into them, and a new key needs a binary installed by hand. A leaked key lets whoever holds it sign updates every client takes: make a new key, publish a release built with it, and tell users to install that one by hand.

The workflow refuses to run without both, and before it publishes it checks the signature against the variable, so a secret that does not belong to the public key fails the release instead of producing one no client can take.

## Making a release

1. Set the version in the workspace `Cargo.toml` (`[workspace.package] version`), run `cargo build` so `Cargo.lock` follows, and commit.
2. Tag that commit `v<version>` and push the tag:

   ```sh
   git tag v0.1.0
   git push origin v0.1.0
   ```

The workflow checks that the tag is the version in `Cargo.toml` and that each binary reports it (`pithagoras-sync --version`), so a mismatch fails before anything is published.

## The helper: `sync-release`

The workflow uses `crates/release` (`cargo run -p sync-release -- ...`), which also works by hand:

```text
sync-release keygen <key file>                     a new key; prints the public key
sync-release public <key file>                     the public key of a key file
sync-release sign (--key <key file> | --key-env <VAR>) <file>      writes <file>.minisig
sync-release verify --public <public key> <file>   checks <file>.minisig
sync-release manifest --version <x.y.z> [--base-url <url>] --out <file> <binary>=<target>...
sync-release sums --out <file> <file>...
```

The public key and the signatures are in minisign's format (a legacy, not prehashed, Ed25519 signature with a trusted comment); the client checks them with the `minisign-verify` crate, and so does `sync-release verify`. Checking them with the minisign tool itself (`minisign -V -P <public key> -m manifest.json`) should work but was not tried. The secret key file is this tool's own format (the key id and the PKCS#8 key, base64, no password), not minisign's.

A manifest made without `--base-url` names the binaries by file name, relative to the manifest: that is a local release folder, which `pithagoras-sync update --manifest <folder>/manifest.json` takes (testing.md).

## What was checked, and what not

The workflow was checked with `actionlint` 1.7.7 (without shellcheck), and its steps were run by hand on Linux: the x86_64 musl build (with clang as the C compiler, the workflow uses `musl-gcc`) and the Windows build (with `cargo xwin` instead of the Windows runner), both with a throwaway key compiled in; the static-binary, version and no-`VCRUNTIME140` checks; `manifest`, `sign --key-env`, `verify` (a wrong key refused), `sums` and `sha256sum -c`; and the release client's `update --check` against that manifest (up to date at 0.1.0, 0.1.1 offered, a manifest signed by another key refused). Against GitHub, `update --check` reached the stable channel's URL (HTTP 404: no release yet) and followed GitHub's release download redirects.

Not run: the workflow itself on GitHub (nothing is published until a tag is pushed), the aarch64 build, and `gh release create`.

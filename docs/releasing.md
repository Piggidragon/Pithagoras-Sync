# Releasing

A release is a version tag. `.github/workflows/release.yml` then checks the workspace (`cargo fmt --check`, clippy, the tests), builds the binaries, signs the update manifest and publishes a GitHub Release. `pithagoras-sync update` reads the manifest of the newest release (`releases/latest/download/manifest.json` of this repository: the stable channel; pre-releases are not "latest", so they never reach it).

## What a release holds

| File | What |
|---|---|
| `pithagoras-sync-x86_64-linux` | Static musl binary, x86_64 |
| `pithagoras-sync-aarch64-linux` | Static musl binary, aarch64 (built on GitHub's arm64 runner) |
| `pithagoras-sync-x86_64-windows.exe` | Windows x86_64, with the C runtime linked in |
| `manifest.json` | The version, when it was released (`released`, Unix seconds) and, per target (`x86_64-linux`, `aarch64-linux`, `x86_64-windows`), each binary's URL, size and sha256 |
| `manifest.json.minisig` | The manifest's signature by the release key |
| `SHA256SUMS` | Checksums of everything above, for `sha256sum -c` |

Every binary has the release key's public half compiled in (`PITHAGORAS_SYNC_UPDATE_KEY`). The client takes a manifest only with a valid signature by that key, a binary only with the size and sha256 the manifest names, and only a newer version (protocol.md, decision 13). It also keeps the release time of the newest manifest it took and refuses one released before it, so a client never goes back to an older signed manifest it already moved past. That protects against a download path that serves stale files (a mirror, a cache, a proxy), not against someone who can change this repository's releases: on GitHub that takes the same write access as pushing a tag, and a pushed tag gets a fresh signature with a fresh release time unless signing waits for an approval (see "Who can sign" below). It does not help a client that never saw the newer manifest either, and a manifest does not expire, so a listing frozen at an old release still verifies; `update --check` shows the release date, which makes a channel that stopped moving visible. Each release must be made later than the one before it, which a release made by the workflow is.

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

The secret reaches one step of the workflow only: the one that runs `sync-release sign`. The tool is built in a job of its own without the secret, and the job that signs checks nothing out and builds nothing, so no build script or proc macro of a dependency runs while the key is readable. The actions are pinned by commit. What remains: the tool's own code, its dependencies included, runs with the key when it signs, so a compromised dependency compiled into `sync-release` could still take it; the lock file and review of dependency updates are the defence there.

### Who can sign

What the owner should set, in the repository's settings (the workflow does not do it yet): a GitHub environment `release` (Settings, Environments) that holds the secret `PITHAGORAS_SYNC_SIGNING_KEY` instead of the repository, with a required reviewer and deployments limited to tags matching `v*`; `environment: release` on the `publish` job only, so no other job can reach the key (the `check` job's test for the secret then has to move into `publish`, since an environment secret is empty outside it); and a tag ruleset (Settings, Rules) so that only admins can create, move or delete `v*` tags.

Why: a tag can point at any commit, also one on a branch nobody reviewed, and the run takes both the workflow and the signing tool from that commit. With a plain repository secret, any account or token that can push a commit and a tag gets a signed release every client installs, or, by changing the workflow, the key itself, and a key cannot be replaced in the field. With the environment, the run stops before the key is handed out until the reviewer approves it, and the reviewer sees which commit is about to be signed; the ruleset keeps a stolen write token from making a `v*` tag at all. Signing offline, by the key holder, would be stronger still.

## Making a release

1. Set the version in the workspace `Cargo.toml` (`[workspace.package] version`), run `cargo build` so `Cargo.lock` follows, and commit.
2. Tag that commit `v<version>` and push the tag:

   ```sh
   git tag v0.0.1
   git push origin v0.0.1
   ```

The workflow checks that the tag is the version in `Cargo.toml` and that each binary reports it (`pithagoras-sync --version`), so a mismatch fails before anything is published.

## The helper: `sync-release`

The workflow uses `crates/release` (built once, then run as `sync-release ...`), which also works by hand (`cargo run -p sync-release -- ...`):

```text
sync-release keygen <key file>                     a new key; prints the public key
sync-release public <key file>                     the public key of a key file
sync-release sign (--key <key file> | --key-env <VAR>) <file>      writes <file>.minisig
sync-release verify --public <public key> <file>   checks <file>.minisig
sync-release manifest --version <x.y.z> [--released <unix secs>] [--base-url <url>] --out <file> <binary>=<target>...
sync-release sums --out <file> <file>...
```

The public key and the signatures are in minisign's format (a legacy, not prehashed, Ed25519 signature with a trusted comment); the client checks them with the `minisign-verify` crate, and so does `sync-release verify`. Checking them with the minisign tool itself (`minisign -V -P <public key> -m manifest.json`) should work but was not tried. The secret key file is this tool's own format (the key id and the PKCS#8 key, base64, no password), not minisign's.

`manifest` writes the current time as `released` unless `--released` gives one. A manifest made without `--base-url` names the binaries by file name, relative to the manifest: that is a local release folder, which `pithagoras-sync update --manifest <folder>/manifest.json` takes (testing.md).

## What was checked, and what not

The workflow was checked with `actionlint` 1.7.7 (without shellcheck), and its steps were run by hand on Linux: the x86_64 musl build (with clang as the C compiler, the workflow uses `musl-gcc`) and the Windows build (with `cargo xwin` instead of the Windows runner), both with a throwaway key compiled in; the static-binary, version and no-`VCRUNTIME140` checks; `manifest`, `sign --key-env`, `verify` (a wrong key refused), `sums` and `sha256sum -c`; and the release client's `update --check` against that manifest (up to date at 0.1.0, 0.1.1 offered, a manifest signed by another key refused). Against GitHub, `update --check` reached the stable channel's URL (HTTP 404: no release yet) and followed GitHub's release download redirects.

The split of the publish job (the tool built in its own job, the key only in the sign step, actions pinned by commit) was checked by parsing the YAML and by running the publish job's steps by hand against the tool built as in its job, after a round trip without the executable bit as artifacts make it (`manifest`, `sign --key-env`, `verify`, `sums`, `sha256sum -c`); actionlint was not run on it again.

Not run: the workflow itself on GitHub (nothing is published until a tag is pushed), the aarch64 build, and `gh release create`.

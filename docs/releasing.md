# Releasing

A release is a tag on a commit of `main`. `.github/workflows/release.yml` then checks that the commit is on `main`, checks the workspace (`cargo fmt --check`, clippy, the tests), builds the binaries, signs the update manifest and publishes a GitHub Release. There are two kinds of tag:

| Tag | Example | Release |
|---|---|---|
| `v<x.y.z>` | `v0.0.2` | A real release, marked latest (`gh release create --latest`). `pithagoras-sync update` reads the manifest of the latest release (`releases/latest/download/manifest.json` of this repository: the stable channel), so it offers this one. |
| `pre-v<x.y.z>`, `pre<N>-v<x.y.z>` | `pre-v0.0.2`, `pre2-v0.0.2` | A pre-release for the owner's testing, never "latest", so the stable channel never offers it. Its notes say how to take it: `pithagoras-sync update --manifest https://github.com/<owner>/<repo>/releases/download/<tag>/manifest.json` (the assets come from the release's own page, not from `releases/latest`). |

`N` is one or more digits (`pre0-v0.0.2` passes too), for a second and third try of the same version. Any other tag shape is refused: the trigger filter lists only these three, and the first step of the `check` job fails on any other tag, so nothing is built. The binaries of a pre-release report the plain version (`0.0.2`): the version is what follows the last `v` of the tag, and the workflow compares that with `Cargo.toml` and with `--version`. The manifest of a pre-release carries that version, with the pre-release's tag in the download URLs.

A client takes a manifest only if its version is newer than its own, and a pre-release and the real release of the same version have the same version number. So a client that took `pre-v0.0.2` will not take `v0.0.2` by `update`: install the real release again, from the release page as the README describes.

## What a release holds

| File | What |
|---|---|
| `pithagoras-sync-x86_64-linux` | Static musl binary, x86_64 |
| `pithagoras-sync-aarch64-linux` | Static musl binary, aarch64 (built on GitHub's arm64 runner) |
| `pithagoras-sync-x86_64-windows.exe` | Windows x86_64, with the C runtime linked in |
| `manifest.json` | The version, when it was released (`released`, Unix seconds) and, per target (`x86_64-linux`, `aarch64-linux`, `x86_64-windows`), each binary's URL, size and sha256 |
| `manifest.json.minisig` | The manifest's signature by the release key |
| `SHA256SUMS` | Checksums of everything above, for `sha256sum -c` |

Every binary has the release key's public half compiled in (`PITHAGORAS_SYNC_UPDATE_KEY`). The client takes a manifest only with a valid signature by that key, a binary only with the size and sha256 the manifest names, and only a newer version (protocol.md, decision 13). It also keeps the release time of the newest manifest it took and refuses one released before it, so a client never goes back to an older signed manifest it already moved past. That protects against a download path that serves stale files (a mirror, a cache, a proxy), not against someone who can change this repository's releases (write access is enough to edit one). A new signature takes more: a commit on `main`, a tag only the owner may create, and the owner's approval of the run (see "Who can sign" below). It does not help a client that never saw the newer manifest either, and a manifest does not expire, so a listing frozen at an old release still verifies; `update --check` shows the release date, which makes a channel that stopped moving visible. Each release must be made later than the one before it, which a release made by the workflow is.

## One-time setup

The release key is a minisign-compatible Ed25519 key. Its secret half lives only in a secret of the GitHub environment `release`; its public half goes into every binary. Make it once, on a machine you trust, from a checkout of this repository:

```sh
cargo run --release -p sync-release -- keygen release.key
```

It writes the secret key to `release.key` (readable by you only; it never overwrites a file) and prints the public key, one line of base64 starting with `RW`. Then, in the repository's Settings:

1. **Repository variable** `PITHAGORAS_SYNC_UPDATE_KEY` (Secrets and variables, Actions, Variables): the public key line. A variable, not a secret: it is public, and every binary carries it.
2. **Environment** `release` (Environments): required reviewer the owner, "Prevent self-review" off (the owner is the only reviewer and pushes the tags), deployment branches and tags limited to the tag patterns `v*`, `pre-v*` and `pre*-v*` (the workflow runs for all three; a deployment tag filter takes no regular expression, so these globs are looser than the shapes the workflow accepts, and its `check` job refuses the rest). This is a repository setting, not workflow content: the owner changes it in Settings.
3. **Environment secret** `PITHAGORAS_SYNC_SIGNING_KEY` of `release`: the whole content of `release.key`. Not a repository secret: one of those would be readable by every job of every workflow.
4. **Tag ruleset** (Rules, Rulesets) on `v*`, `pre-v*` and `pre*-v*` (the same patterns as the environment; also a repository setting the owner changes): only the owner may create such tags (bypass list), nobody may update or delete them, and non-fast-forward is blocked.

Keep `release.key` offline (a password manager or an encrypted backup) and delete the working copy. Never commit it, and never use it in tests: tests make throwaway keys.

Losing the secret key means the clients in the field cannot take another update: they trust only the key compiled into them, and a new key needs a binary installed by hand. A leaked key lets whoever holds it sign updates every client takes: make a new key, publish a release built with it, and tell users to install that one by hand.

The workflow refuses to run without the variable (the `check` job) or the secret (the `publish` job, the only one that can see it), and before it publishes it checks the signature against the variable, so a secret that does not belong to the public key fails the release instead of producing one no client can take.

To rotate the key: clients trust only the key compiled into them, so the change takes one release built with the new public key and signed with the old key. The workflow cannot make that one (it checks the signature against the public key it compiles in), so make it by hand from the tagged commit on `main`: build the three binaries with the new public key in `PITHAGORAS_SYNC_UPDATE_KEY`, then `sync-release manifest`, `sign --key <old key file>` and `sums` as the workflow does, and attach the files to the tag's release (reject the workflow's own run for that tag at the approval). Then set the new public key as the variable and the new secret as the environment secret; later releases come from the workflow again. After a leak the old key proves nothing: make a new key and have users install by hand.

The secret reaches one step of the workflow only: the one that runs `sync-release sign`. The tool is built in a job of its own without the secret, and the job that signs checks nothing out and builds nothing, so no build script or proc macro of a dependency runs while the key is readable. The actions are pinned by commit. What remains: the tool's own code, its dependencies included, runs with the key when it signs, so a compromised dependency compiled into `sync-release` could still take it; the lock file and review of dependency updates are the defence there.

### Who can sign

- **Only a commit on `main`.** The `check` job fails unless the tagged commit is `main` or an ancestor of it ("tag v0.0.2 is not on main: merge to main first, then tag"). Every other job needs that one, so a tag on another branch builds nothing and never reaches the key. This matters because a run takes the workflow and the signing tool from the tagged commit.
- **Only with the owner's approval.** `publish` is the only job in the environment `release`. It waits until the owner approves it in the Actions tab, and the run shows the commit about to be signed. No other job can read the secret.
- **Only tags the owner made.** The tag ruleset keeps everyone else, another account's stolen write token included, from creating a `v*`, `pre-v*` or `pre*-v*` tag, and nobody can move or delete one, so a published version always names the same commit.
- **The owner's GitHub account holds all of it.** Whoever controls it can merge to `main`, tag and approve. Keep two-factor authentication on, with a hardware key or an authenticator rather than SMS, and keep personal access tokens few and short-lived. Signing offline, by the key holder, would be stronger still.

## Making a release

1. Set the version in the workspace `Cargo.toml` (`[workspace.package] version`), run `cargo build` so `Cargo.lock` follows, and merge that to `main`.
2. Tag the merged commit on `main` and push the tag. `v<version>` is the real release, `pre-v<version>` (or `pre2-v<version>` for another try) a pre-release to test first:

   ```sh
   git switch main && git pull
   git tag pre-v0.0.2 && git push origin pre-v0.0.2   # a pre-release
   git tag v0.0.2 && git push origin v0.0.2           # the real release
   ```

3. In the Actions tab, open the run "Release". When check, builds and tool are done, `publish` waits for review: check that the commit is the one you tagged, then approve the deployment to `release`.
4. When the run is green, check the release: the three binaries, `manifest.json`, `manifest.json.minisig` and `SHA256SUMS`. Then `sha256sum -c SHA256SUMS` on the downloaded files, and for a real release `pithagoras-sync update --check` from an installed client, which should offer the new version (a pre-release is not offered: take it with `update --manifest <url>`).

The workflow checks that the version of the tag (what follows its last `v`) is the version in `Cargo.toml` and that each binary reports it (`pithagoras-sync --version`), so a mismatch fails before anything is published.

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

The split of the publish job (the tool built in its own job, the key only in the sign step, actions pinned by commit) was checked by parsing the YAML and by running the publish job's steps by hand against the tool built as in its job, after a round trip without the executable bit as artifacts make it (`manifest`, `sign --key-env`, `verify`, `sums`, `sha256sum -c`); actionlint was not run on it again. The same holds for the `main` check and the `release` environment: the YAML was parsed and read, not linted, and neither has run on GitHub yet.

The tag rules (the three shapes, the version after the last `v`, pre-release or latest) were run by hand on the `check` and `publish` steps with a fake `gh`, for good and bad tags; `gh release create --latest` was not run.

Not run: the workflow itself on GitHub (nothing is published until a tag is pushed), the aarch64 build, and `gh release create`.

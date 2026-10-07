# Updating the computer-use pins

The computer-use servers move without a new client: the owner publishes a new signed pins document ([mcp-pins.md](mcp-pins.md)), and every client takes it with `pithagoras-sync update`, `computer-use update`, or by itself once a day. This page is the owner's side. Releases of the client itself are [releasing.md](releasing.md).

## What the client does with a new document

1. It fetches `mcp/mcp.json` and `mcp/mcp.json.minisig` from `main` of this repository (`raw.githubusercontent.com`), checks the signature with the release key compiled into it (the same key and check as the update manifest), then the document's rules (fields, hosts, hashes, the serial above every one it took before). A document that fails any of it is ignored, and the client keeps the pins it has.
2. For each installed server whose pin changed (another version, or the same version from other files, such as a new Python patch or a new locked list of wheels), it installs the new pin into a fresh folder (never patching the old one), checks every file's hash, starts it once, and records it. The version before stays for one rollback (`computer-use rollback`); older ones are removed.
3. The running client switches to it once no call is in flight and no chat waits on a consent question; until then the old one serves. An older version that cannot be removed yet (Windows: still running) stays until the next update. If the new version's allow-list lacks a tool the old one had, the portal hears of it through `mcp.changed` and the tool is refused from then on.
4. A failure leaves the old version running and is shown in `computer-use status` (the daily look) or by the command. A server the owner rolled back (`computer-use rollback`) is left alone until they install again.

Installs, updates, rollbacks and uninstalls take turns (a lock file in the servers' folder): the daily look and the owner's commands never work on a server's folders or its record at the same time; the second one says it waits.

Consent, the allow-list rules and the settings are never touched by an update. The hard deny-list in the client beats any document.

## Making a document

The input is `mcp/servers.json`: each server's name, platform, exact version, the download URL of every file (with `kind`, `path` and `arch`), how to run it, the allowed and input tools, the focus-check and self-test tools, and the setup steps. Everything but the hashes and sizes, which the tool measures.

1. **Read upstream.** For `computer-use-linux`: the release page of the version to pin (its asset names per architecture), and its README for the tool names and the setup (GNOME Shell extension, AT-SPI, the remote desktop portal). For Windows-MCP: its `pyproject.toml` (`requires-python`), `.python-version`, `uv.lock` or its requirements at the pinned version, its tool names in the source, and its telemetry switch.
2. **Windows: the Python.** Take the embeddable CPython zip for Windows x86_64 from python.org, of the newest patch of the minor version Windows-MCP names (or exactly the version it pins). Every dependency in its lock must have a wheel for that Python (`cp3XY-win_amd64`, `abi3` or `py3-none-any`); if one has none, stop: the client does not build anything. List Windows-MCP's own wheel and every dependency's wheel from `files.pythonhosted.org` as `wheel` files with `path` `python/Lib/site-packages`, and the `pythonXY._pth` under `write` (with `pythonXY.zip`, `.`, `Lib\site-packages` and `import site`). List the modules the server imports under `selftest.imports`; the embeddable Python has no `tkinter`, so the install fails by name if the server needs it. Set `ANONYMIZED_TELEMETRY=false` (or what the pinned version's source names) under `run.env`.
3. **Allow-list.** Only the exact tool names of the pinned version that look or point and type: screenshots, the window list or state, pointer move, click, scroll, drag, typing and keys. Never anything that installs, reconfigures, runs programs or commands, reads files or the clipboard, or acts on elements by their own logic; the tool refuses names on the client's hard deny-list anyway. A tool the new version adds stays off unless you list it. Under `observe`, name only the tools that look without acting (screenshots, the window list): every other allowed tool gets the focus check first.
4. **Build, sign, check.** From a checkout of `main`, with the release key at hand (offline, as for a manual release):

   ```sh
   cargo run --release -p sync-release -- mcp --input mcp/servers.json --previous mcp/mcp.json --out mcp/mcp.json.new
   mv mcp/mcp.json.new mcp/mcp.json
   cargo run --release -p sync-release -- sign --key release.key mcp/mcp.json      # or --key-env VAR
   cargo run --release -p sync-release -- mcp-verify --public "$PITHAGORAS_SYNC_UPDATE_KEY" mcp/mcp.json
   ```

   `mcp` downloads and hashes every file, takes the serial after `--previous` (or `--serial N`, which must be higher), refuses a `TODO-PIN` left in a URL, a host off the list and a hard-denied tool, and checks the result with the client's own rules. `mcp-verify` checks the signature and the document as the client does and prints what it pins. Without `--previous` (the first document) the serial is 1.
5. **Try it** on a test machine before it reaches every client: point a debug build at the file (`PITHAGORAS_SYNC_TEST_MCP_PINS=/path/to/mcp.json`) or install from a branch, then `computer-use install`, `setup` and `test` ([testing.md](testing.md)).
6. **Publish**: commit `mcp/mcp.json` and `mcp/mcp.json.minisig` to `main`. Clients take it at their next daily look or `update`.

## Workflows (not in this repository yet)

Two workflows are planned and added separately: a manually started one in the `release` environment that runs step 4 with the owner's approval (the key only in the step that signs, as in the release workflow), and a scheduled one that only checks upstream for newer versions and opens a pull request that updates `mcp/servers.json`, for the owner to review and sign.

## Keys and rollback

The pins are signed with the release key; its rules ([releasing.md](releasing.md)) hold here too: never in tests, offline, rotated by a release. A document cannot be taken back once clients took it (they refuse a lower serial): publish a newer one that pins the previous version again. On one machine, `pithagoras-sync computer-use rollback` goes back one version at once.

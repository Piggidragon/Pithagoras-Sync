# The computer-use pins

Which MCP server the client installs for computer use ([computer-use.md](computer-use.md)), in which exact version, from which files, run how, and which of its tools the portal may call. A server is an entry in this table, not code: a new version, a new allow-list or a new Python for Windows-MCP is a new entry.

The pins come from two places, and nowhere else:

1. **The baseline**, compiled into the client: `crates/mcp/pins/baseline.json`. It has serial 0. Values not known when the client was built are `TODO-PIN`; a server with one cannot be installed until a signed document pins it.
2. **The signed document**, `mcp.json` with `mcp.json.minisig`, signed with the release key of the update manifest and checked with the key built into the client. The client fetches it from `https://raw.githubusercontent.com/Piggidragon/Pithagoras-Sync/main/mcp/mcp.json` (the signature, not the host, is the trust; only debug builds can be pointed elsewhere, for the tests), keeps the newest one it took in its state folder (`mcp/pins.signed.json`, the document and its signature in one file written at once, checked again on every read) and uses it from then on, also without network. Once a signed document was taken, the baseline is not used again: a kept document that is lost or no longer verifies leaves no server pinned (each installed one is shown unavailable) until `update` or the daily look takes one again, so a server a signed document took back does not come back with the baseline.

How the owner makes and signs it: [mcp-updates.md](mcp-updates.md).

## Format

```json
{
  "serial": 3,
  "issued_ms": 1760000000000,
  "servers": [
    {
      "name": "computer-use-linux",
      "platform": "linux",
      "version": "0.4.1",
      "files": [
        {"arch": "x86_64", "kind": "executable", "path": "computer-use-linux",
         "url": "https://github.com/agent-sh/computer-use-linux/releases/download/v0.4.1/computer-use-linux-x86_64",
         "sha256": "<64 hex>", "size": 12345678}
      ],
      "write": [],
      "run": {"program": "computer-use-linux", "args": [], "env": {}},
            "allow": ["screenshot", "list_windows", "mouse_move", "mouse_click", "type_text", "press_key"],
      "observe": ["screenshot", "list_windows"],
      "focus": {"windows": {"tool": "list_windows"}, "focused": {"tool": "get_focused_window"}},
      "selftest": {
        "screenshot": {"tool": "screenshot"},
        "pointer": {"position": {"tool": "get_cursor_position"}, "move_to": {"tool": "mouse_move", "args": {"x": "$x", "y": "$y"}}},
        "imports": []
      },
      "setup": [
        {"id": "accessibility", "title": "...", "text": "...", "desktop": "gnome",
         "check": {"argv": ["/usr/bin/gsettings", "get", "org.gnome.desktop.interface", "toolkit-accessibility"], "expect": "true"},
         "run": ["/usr/bin/gsettings", "set", "org.gnome.desktop.interface", "toolkit-accessibility", "true"]}
      ]
    }
  ]
}
```

- `serial`: only ever grows. The client keeps the highest serial it took (a 0600 file, `mcp-pins-serial` in its state folder) and refuses a document with a lower one, so an older signed document served again is not taken. `issued_ms`: when it was made.
- `name`: `a-z`, `0-9`, `-`. `platform`: `linux` or `windows`; one entry per name and platform. `version`: the exact upstream version. Its folder on the device is `<version>-<the start of the pin's sha256>`, so a pin that changes for the same version (a new Python patch) installs into a fresh folder beside the old one.
- `files`: what the install downloads. `arch` (`x86_64`, `aarch64`; absent for every one) picks the file for the machine. `kind`: `executable` (written 0755), `file` (0644), `zip` (unpacked into `path`: the embeddable Python) or `wheel` (a Python wheel unpacked into `path`, site-packages: its `.data/purelib` and `.data/platlib` go there too, scripts and headers are left out). `path` is relative and stays inside the folder. `url` is https to `github.com`, `*.githubusercontent.com`, `pypi.org`, `files.pythonhosted.org` or `www.python.org`; every redirect is held to the same list. `sha256` and `size` are checked before anything is written under its final name.
- `write`: small text files the install writes itself after unpacking (on Windows the `pythonXY._pth` that puts `Lib\site-packages` on the path and switches `import site` on).
- `run`: the program in the folder and its arguments (`{dir}` is the folder), and environment variables added to the clean environment the server gets (the desktop session's variables and a fixed `PATH`; nothing else of the client's). Only a `..._TELEMETRY` switch and `DO_NOT_TRACK`, `NO_COLOR`, `PYTHONUTF8`, `PYTHONIOENCODING`, `PYTHONUNBUFFERED` are taken: nothing that changes what a program loads or runs. This is where telemetry is switched off (Windows-MCP: `ANONYMIZED_TELEMETRY=false`). The server runs with its working folder outside its hashed folder.
- `allow`: the tools the portal may call, exact names of this version; every other tool is never listed and never called. `observe`: which of them only look (screenshots, the window list); before every other allowed tool the focus check runs, so a tool the pins forget to name is checked, not let through.
- `focus`: the tools the client calls itself before input: the window list and, where the server has one, the focused window. They are not listed to the portal. A text that names `Pithagoras Sync` refuses the input, and so does an answer the client cannot read.
- `selftest`: what `computer-use test` calls (all on the allow-list): a screenshot, and the pointer position and move (`$x`, `$y` are filled in). `imports`: the Python modules the install checks with the server's own Python, so a missing one fails the install by its name.
- `setup`: the steps of `computer-use setup`. `check` (a command and the output it must print) says whether a step is done; `run` is carried out only after the owner's yes. Programs are absolute paths, or `{dir}/...` in the server's folder; never one found on `PATH`.

## Rules the client keeps

- A document is taken whole or not at all. It is ignored, with a note in `computer-use status` and the log, when its signature does not verify, its serial is lower than one taken before, it has a field the client does not know (at any depth), a download host off the list, a path that leaves the folder, a malformed hash or size, or a tool name or setup step that breaks the rules above.
- **The hard deny-list** in the client's code always wins: a document can narrow the allow-list or keep it, never open one of these. Tool names are compared lowercase, without `-`, `_`, spaces and a trailing `tool` (so `Powershell-Tool` is `powershell`): `setup_window_targeting`, `perform_action`, `set_value`, `app`, `launch`, `shortcut`, `clipboard`, `scrape`, `multiedit`, `powershell`, `shell`, `filesystem`, `file`, `files`, `registry`, `process`, `processes`, `run`, `exec`, `execute`, `command`, `terminal`, `install`, `setup`; and any name containing `powershell`, `shell`, `registry`, `clipboard`, `filesystem`, `process`, `install`, `setup`, `exec`, `command`, `scrape` or `launch`. `sync-release mcp` refuses to make a document that names one; a client that gets one anyway leaves the tool off and says so.
- A new tool in a new version is off until the signed document lists it and the deny-list allows it.
- The baseline alone may hold `TODO-PIN`; a signed document never, anywhere in it.
- A document that pins another version than the one installed (an update that failed, or `auto_update` off) narrows it all the same: the installed version keeps only the tools both allow, and the focus check runs wherever either asks for it. A signed document that no longer names an installed server stops it (unavailable until it is uninstalled or pinned again).
- The serial floor is the highest of the recorded serial and the kept document's, so losing the record does not let an older document replace the kept one.

## The baseline of 0.0.3

The built-in pins name `computer-use-linux` and Windows-MCP, but their versions, URLs, hashes and (for Windows) the embeddable Python and the wheels are `TODO-PIN`: they could not be read from upstream when 0.0.3 was written. The tool names on the allow-lists are those the 0.0.3 brief and the projects' documentation name, unverified against a pinned release. So until the owner publishes a signed document, `computer-use install` says the server is not pinned yet and installs nothing. `mcp/servers.json` in the repository is the input for that document, with the same `TODO-PIN` values to fill in.

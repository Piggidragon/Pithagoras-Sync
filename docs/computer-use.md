# Computer use

Computer use lets the agent of a chat see this computer's screen and use its pointer and keyboard: take a screenshot, move the pointer, click, scroll and type. It comes with 0.0.3.

Pithagoras Sync does not do this itself. It installs an existing program for it, an MCP server, and runs it in the background:

- **Linux:** [`computer-use-linux`](https://github.com/agent-sh/computer-use-linux) (Rust, MIT), one program file.
- **Windows:** [Windows-MCP](https://github.com/CursorTouch/Windows-MCP) (Python, MIT), with a Python of its own that the client brings along, so you do not need to install Python.

The client talks to that server (it is the MCP client); the portal never does. The portal asks the client (`mcp.list`, `mcp.call`, [protocol.md](protocol.md)), and the client checks every call before the server sees it.

## The risk, in plain words

**Allowed, computer use is as strong as Full mode.** The agent can click and type anything you can: open a terminal and type a command into it, open your browser where you are logged in, change settings. The mode (`ask`, `folders`, `full`) does not limit it, and neither do granted folders or protected paths: those cover the file tools and the shell, not your pointer and keyboard. And what is on your screen goes to the portal and its model: a screenshot shows whatever windows are open.

So it is off until you switch it on, separately from everything else, and only on this computer:

- **`off`** (the default): every call is refused.
- **`ask`**: the first computer-use call of each chat asks you, in the portal's Devices tab or with `pithagoras-sync approvals`. You answer once, for this chat, or deny. The question names the tool and shows its arguments (the text it would type, the keys it would press). Nobody answering within the approval timeout is a denial.
- **`allow --minutes N`**: no questions, for at most 8 hours; then it is `off` again.

`pithagoras-sync panic` stops every computer-use call and the server at once, and turns an `allow` into `off`; `unlock` does not switch it on again.

What else holds while it is on:

- **Only some tools.** Each server version has an allow-list of exact tool names in the client: screenshots, the window list, pointer moves, clicks, scrolls and drags, typing and keys. Everything else the server offers is never shown to the portal and never called, for example on Linux `setup_window_targeting`, `perform_action` and `set_value`, on Windows `App`, `Shortcut`, `Clipboard`, `Scrape`, `MultiEdit`, PowerShell, FileSystem, Registry and Process. A tool that appears in a newer server version stays off until the client's pins allow it, and a built-in deny-list keeps the dangerous ones off even then.
- **Not into Pithagoras Sync's own windows.** Before every click or key, the client asks the server which windows are open and which has the focus, and refuses while a window of Pithagoras Sync is open (its install and pairing windows, any question it shows). If it cannot tell, it refuses too.
- **The chat counts as having seen untrusted content.** A screenshot can show anything, including text written to trick the agent. After a computer-use call, that chat's next command or write asks you even in Full mode (`policy.full.taint_prompts`, on by default).
- **An indicator.** At the start of each burst of calls a desktop notification (Linux) says which chat uses the screen; `pithagoras-sync status` shows it too ("Computer use: ... in use by chat ..."). Every decision is in the audit log.
- **No way around the rest.** The file tools never reach the server's folder (in no mode, as the stored sudo password), so a portal cannot read or replace the server through them; and only the allowed tools above are ever called, never one that runs commands or reads files.

## Install

```sh
pithagoras-sync computer-use install --print    # what it would download, and from where
pithagoras-sync computer-use install
```

or `pithagoras-sync install --computer-use` together with the client, or "Also install computer use?" in the install window. It downloads the pinned version of the server from its project's releases (GitHub, and on Windows python.org and PyPI), checks each file's size and sha256 against the pin before anything is written, puts it into the client's own folder (`~/.local/state/pithagoras-sync/mcp/<server>/<version>/`, `%LOCALAPPDATA%\pithagoras-sync\mcp\...` on Windows; private to you), starts it once to see that it answers and which tools it has, and records the version and a hash of the whole folder in `config.toml`. Before every start the client checks that hash again: a server changed after install is not run. Nothing comes from your `PATH`, and nothing is installed system-wide.

Versions are exact pins, never "latest". The pins are built into the client and can be replaced by a newer list the owner of this project signs with the release key ([mcp-updates.md](mcp-updates.md)), without a new client.

## Setup

```sh
pithagoras-sync computer-use setup
```

walks through what the server needs on this desktop, step by step, with the exact command or setting, and asks before it changes anything.

- **GNOME** (validated upstream on Ubuntu 25.10, GNOME 50, Wayland):
  1. Accessibility (AT-SPI): `gsettings set org.gnome.desktop.interface toolkit-accessibility true` (the setup offers to run it).
  2. The server's GNOME Shell extension, as its README says; then log out and in (GNOME on Wayland loads new extensions at login).
  3. Pointer and keyboard: the first input shows GNOME's remote desktop prompt; allow pointer and keyboard there. `computer-use test` brings it up.
  - GNOME 46 (Zorin OS 17/18) is older than what upstream validated: the extension or the portal prompt may behave differently.
- **KDE Plasma:** not validated, by upstream or here. The setup shows what the server's README says.
- **Windows 10/11:** nothing to set up. Windows-MCP drives your own desktop through UI Automation. It reaches only the session you are logged into: not a UAC prompt (the secure desktop), not another user's session, not the lock screen; while the screen is locked, calls fail.

## Test and status

```sh
pithagoras-sync computer-use test [--verbose]   # screenshot, pointer 10 px right, read back, and back
pithagoras-sync computer-use status [--json]    # installed and pinned version, files, consent, whether it answers, setup
```

`test` runs on the running client's server (or starts one itself when no client runs) and says which step failed: no image (the screenshot permission or the extension), the pointer not where it was moved (the remote desktop prompt not allowed). `--verbose` also lists every tool the server offers and which are allowed here.

## The consent

```sh
pithagoras-sync computer-use ask                # each chat asks before its first call
pithagoras-sync computer-use allow --minutes 30 # no questions for 30 minutes (at most 480)
pithagoras-sync computer-use off
```

These are settings (`policy.computer_use.consent`, [permissions.md](permissions.md)) the portal can read but never change, also where it may change other settings. `ask` and `allow` ask for your password on a desktop, as every policy change does.

## Updates

`pithagoras-sync update` updates the server too, also when there is no newer client, and the running client looks once a day at a random time (off with `config set policy.computer_use.auto_update false`). A new version goes into a new folder, is tested there, and is switched to in one step once no call is running; the version before stays for `pithagoras-sync computer-use rollback`. A failed update keeps the old one and says why in `computer-use status`. Your consent and settings stay as they are; the allow-list is the new version's own.

```sh
pithagoras-sync computer-use update [--check]
pithagoras-sync computer-use rollback
```

## Uninstall

```sh
pithagoras-sync computer-use uninstall          # the server only
```

`pithagoras-sync uninstall` and `uninstall --purge` remove it too.

## What is validated

Tested in this repository: everything above against a fake MCP server (`sync-fake-mcp`), a local download server and the mock portal, on Linux, without a screen; the Windows code is cross-built and its pure parts are tested, but it was not run on Windows. Not tested yet, and listed for the first real runs: the real `computer-use-linux` and Windows-MCP, GNOME 46 and 50, KDE, Windows 10 and 11, and the exact tool names of the pinned versions (the built-in pins still hold `TODO-PIN` values that a signed pins document has to fill before anything can be installed; see [mcp-updates.md](mcp-updates.md)).

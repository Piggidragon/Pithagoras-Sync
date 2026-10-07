# Changelog

What changed in each release of Pithagoras Sync, newest first. Every release has a section here: the release workflow stops a version tag whose section is missing, and uses the section as the release notes. How to write one: [docs/releasing.md](docs/releasing.md).

## 0.0.3 - unreleased

Computer use: the agent of a granted chat can see the screen and use the pointer and keyboard, through an MCP server the client installs, checks and runs itself, behind a consent of its own.

### Added

- **Computer use** on Linux (`computer-use-linux`) and Windows 10/11 (Windows-MCP, with an embeddable Python the client brings, so no Python setup). `pithagoras-sync computer-use install` (or `install --computer-use`, or "Also install computer use?" in the install window) downloads the pinned server, checks every file's sha256 before writing it, tests that it starts, and records a hash of its folder that is checked before every start. `uninstall` and `uninstall --purge` remove it.
- **A consent of its own**, off by default and set on the device only: `computer-use ask` (each chat asks: once, for this chat, or deny), `allow --minutes N` (at most 8 hours, then off), `off`. The portal can read it, never change it. `panic` stops every call and turns an allow into off.
- **What holds while it is on:** an allow-list of exact tool names per server version (default deny, and a built-in deny-list no pins can open), arguments checked against the tool's schema, no clicks or keys while a Pithagoras Sync window is open (or when the client cannot tell), every call marks its chat as having seen untrusted content (so its next command asks in Full mode), a desktop notification at the start of each burst of calls (Linux), and `status` naming the chat.
- **`computer-use setup`, `test` and `status`**: the steps the server needs on GNOME (with the commands, run only after a yes), a screenshot and a pointer moved 10 px and read back, and how it all stands.
- **Updates of the server without a new client:** a pins document signed with the release key; `pithagoras-sync update` takes it and moves the server, and the client looks once a day at a random time (`policy.computer_use.auto_update`). `computer-use rollback` goes back one version. `sync-release mcp` makes the document ([docs/mcp-updates.md](docs/mcp-updates.md)).
- **The protocol** for the portal side: `mcp.list`, `mcp.call`, `mcp.changed`, the `mcp` capability ([docs/protocol.md](docs/protocol.md)); the mock portal speaks it.

### Known limits

- The built-in pins hold `TODO-PIN` values (versions, URLs, hashes, Windows' Python and wheels): until the owner publishes a signed pins document, `computer-use install` installs nothing. The allowed tool names are not yet checked against the pinned releases.
- Tried against a fake MCP server only. Not tried: the real servers, GNOME 46 (upstream validated GNOME 50), KDE Plasma (not validated upstream either), and anything of it on Windows (cross-built, its pure parts tested).
- The screenshot is passed on as the server makes it; there is no downscaling on the device yet.

## 0.0.2 - 2026-10-07

The graphical install: a person who never opens a terminal can install, pair, set up sudo access and uninstall the client. A server install stays command-line only and works as before.

### Added

- **Install by double click** on Windows 10/11, GNOME and KDE, in English and German, in few windows: on GNOME one form takes the pairing link and the login password, a second window confirms the parsed portal, a third says whether it connected; KDE asks install and link in one window; Windows asks install and pair in one box when a valid pairing link is in the clipboard. The link may be left out to install only. `pithagoras-sync gui` starts the same flow; with no arguments, a start without a terminal does.
- **Pairing by link.** The client registers itself for `pithagoras-sync://` links (a desktop entry and an icon on Linux, the registry under `HKCU` on Windows), so a click on the portal's pairing link opens it. The link is untrusted: it is parsed strictly and nothing is paired before a question that shows the parsed portal and device name and the current mode.
- **A menu** for an installed and paired client, with the status in its own text: pair again, sudo access (Linux), update (a signed release, after a Yes to its version), open the log, uninstall (with or without `--purge`). Close ends it; what an action reports shows at the top of the next window instead of a window of its own.
- **An icon** for the menu entry and the windows: `install` writes it as SVG and in 48 to 256 pixels (and rebuilds the user's icon cache where there is one), so GNOME and KDE show it; the Windows `.exe` carries it as a resource, and its message boxes show it.
- **Sudo access in a window** (Linux): the password goes into a hidden entry, is checked with `sudo`, and only then kept; the window can switch sudo access off and forget the password. Pairing in a window on a Linux desktop asks for the login password and checks it with `su`.
- **The OS keyring.** `token_storage = keyring` keeps the connector token in the Secret Service (GNOME Keyring, KWallet) or, on Windows, in the Credential Manager, which is the Windows default with a fallback to the file. `policy.privilege.secret_storage = keyring` keeps the elevation password there (Linux). Neither falls back silently when you chose the keyring.
- **`docs/install.md`** for people who are not at a terminal.

### Changed

- A portal URL path is limited to ASCII letters, digits and `-._~/` and `%XX`, with no `.` or `..` segment. A pairing saved by 0.0.1 with such a path no longer connects: pair again.
- Every pairing records its time in the config (`paired_ms`), so a re-pairing with the same device id takes the new token at once. A client of 0.0.1 cannot read a config written by this version; going back needs a new pairing.
- Keyring entries carry the config folder, so two clients of one user keep apart entries.

### Known limits

- A console window can flash when the logon task starts the client on Windows (Windows Terminal about 0.2 s, the classic console about 25 ms); a launcher without a console comes later (issue #6).
- The window texts for the CLI's errors, and the notes of installing, pairing and uninstalling, are English; SmartScreen warns about the unsigned Windows file (issue #7).
- Tried with Edge, Chrome and Firefox on Windows 11, and with Ubuntu's GNOME tools and kdialog under a virtual screen, and by hand on GNOME (Wayland); Windows 10, links from Chrome and Firefox on Linux and a real Plasma session are not tried yet.

## 0.0.1 - 2026-10-06

The first release: the background client, without a GUI (phase 1 of the desktop app). It is the device side of the portal's Devices add-on.

### Added

- **Pairing and connection.** `pair` takes the pairing URI from the portal's Devices page. The client reconnects by itself, pins the portal's certificate key, and starts with the machine: a systemd user or system unit on Linux (`install`, `setup --create-user`), a logon task on Windows.
- **What the agent can use on a device.** Files, the shell and git, served as the pi tools you allow. A chat gets a device only when you grant it in the portal.
- **Permissions that stay on the device.**
  - **Ask** (the default): every call asks for approval, in the portal's chat or on the device with `approvals`, `approve` and `deny`. No answer within 2 minutes is a denial.
  - **Folders**: files only in the folders you grant (read-only unless `--rw`), commands only in folders you grant `--exec`, under Landlock on Linux 5.13 or newer.
  - **Full**: everything your user can do, back to Ask after 8 hours by default, with protected paths and risky-command prompts still on.
  - Every other permission is a setting: `config get` and `config set`, listed in [docs/permissions.md](docs/permissions.md). The portal may read the settings by default, and change them only where you allow it.
- **Commands as root.** `pithagoras-sync sudo set | activate | deactivate | clear | status` (Linux). The password is typed on the device, never in the portal, never shown to the agent, and scrubbed from output and logs. Every `sudo` command asks for approval.
- **`panic` and `unlock`.** Close the link and kill every command at once, until `unlock`.
- **Audit log.** Every decision and every settings change, with old and new value, in `~/.local/state/pithagoras-sync/audit.jsonl`.
- **Signed updates.** `update --check` and `update` take only a release whose manifest is signed by the release key built into the program, refuse a replayed older release, check size, checksum and reported version, and restart the client.
- **`uninstall --purge`.** Removes everything the client left except the program, and says where that is.
- **Windows (x86_64).** The same remote access without administrator rights. There is no shell sandbox yet, so in Folders mode every command asks, and `sudo` is Linux only ([docs/windows.md](docs/windows.md)).
- **Binaries.** Static Linux (x86_64, aarch64) and Windows x86_64, with `SHA256SUMS` and a signed `manifest.json`.

### Known limits

- Windows has no shell sandbox, and a console window can flash when the logon task starts the client (issue #6).
- The aarch64 Linux binary was built by the release workflow but not tried on a machine.
- The Devices add-on of the portal is `thecodacus/pithagoras#87`; until it is merged, use a portal that runs that branch.

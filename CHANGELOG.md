# Changelog

What changed in each release of Pithagoras Sync, newest first. Every release has a section here: the release workflow stops a version tag whose section is missing, and uses the section as the release notes. How to write one: [docs/releasing.md](docs/releasing.md).

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

# Pithagoras Sync

Lets the agent of your [Pithagoras](https://github.com/thecodacus/pithagoras) portal reach your own computers, the way a file-sync client reaches the cloud: pair once, it starts with the machine, reconnects by itself, and from then on the agent can use that computer's files, shell and git when a chat is granted the device.

**Status: phase 1 in progress, no portal yet.** The portal side (the `/sync/v1` hub, the Devices page, the tool wrapper) is not written, so this client cannot be used yet. It is tested against a mock portal only. Phase 1 is the background client without a GUI; the desktop app with overlay, voice and computer use is phase 2.

## Platforms

- **Linux** (x86_64): one static binary, for desktops and servers, started as a systemd user or system unit.
- **Windows** (x86_64): the same remote access, started by a logon task. It builds and passes its checks, but has not run on Windows yet; see [docs/windows.md](docs/windows.md).

## What the portal may do

You decide on the device, never the portal:

- **Ask** (the default on a desktop): every call asks you, through a system notification with Allow and Deny. Without a notification service, the call is denied.
- **Folders** (the default on a server): files only inside the folders you grant, read-only unless you add `--rw`. Commands run under Landlock (Linux 5.13 or newer) and can write only inside your read-write folders.
- **Full**: everything your user can do. It falls back after 8 hours by default. Protected paths (`~/.ssh`, keyrings, browser profiles, shell start-up files and more) and prompts for risky commands stay on unless you turn them off.

`pithagoras-sync panic` stops everything at once: it closes the link and kills every command until you run `pithagoras-sync unlock`. Every decision goes to a local audit log, `~/.local/state/pithagoras-sync/audit.jsonl`.

## Linux laptop or desktop

1. Download the binary and make it executable. There is no release yet; until there is, build it as described below and use `target/x86_64-unknown-linux-musl/release/pithagoras-sync`.

   ```sh
   curl -LO https://github.com/Piggidragon/Pithagoras-Sync/releases/latest/download/pithagoras-sync-x86_64
   chmod +x pithagoras-sync-x86_64
   ```

2. In the portal, open Settings, Devices, "Pair a device", and copy the pairing URI. Then pair. Quote the URI, since it contains `&`. On a desktop, this and every later policy change asks for your password in the terminal.

   ```sh
   ./pithagoras-sync-x86_64 pair 'pithagoras-sync://pair?portal=...&code=...&spki=...'
   ```

3. Install it. This copies the program to `~/.local/bin/pithagoras-sync` and starts it now and at every login, as a systemd user unit.

   ```sh
   ./pithagoras-sync-x86_64 install
   ```

4. Check that it runs. To use Folders mode, grant folders first:

   ```sh
   pithagoras-sync status
   pithagoras-sync folder add ~/src/myproject --rw
   pithagoras-sync mode folders
   ```

`pithagoras-sync install --print` shows what `install` would do without doing it; `pithagoras-sync uninstall` undoes it.

## Linux server

Run the client as an unprivileged user, ideally a dedicated one. Root works too (Proxmox containers run as root by default), and `pair` warns about it: the agent then acts with root's rights wherever the policy lets it.

```sh
sudo ./pithagoras-sync-x86_64 setup --create-user   # shows what it creates and asks first
sudo setfacl -R -m u:pithagoras-sync:rwX /srv/project
sudo -H -u pithagoras-sync pithagoras-sync folder add /srv/project --rw
sudo -H -u pithagoras-sync pithagoras-sync pair '<uri from the portal>'
sudo systemctl start pithagoras-sync
```

`setup --create-user` creates the user with a locked password and installs the program to `/usr/local/bin` with a system unit; `sudo pithagoras-sync setup --remove` undoes it. For an existing user, use `sudo pithagoras-sync install --system --user <name>`; as your own user without root, use `pithagoras-sync install`, which turns on lingering so the unit runs without a login. Nobody can answer a prompt on a server, so there is no Ask mode there: anything that would prompt is denied.

## Windows

Download `pithagoras-sync.exe`, then in PowerShell:

```powershell
.\pithagoras-sync.exe pair 'pithagoras-sync://pair?portal=...&code=...'
.\pithagoras-sync.exe install
```

`install` copies it to `%LOCALAPPDATA%\Programs\pithagoras-sync` and adds a logon task; it needs no admin rights. Commands run in PowerShell. Windows has no Ask mode and no shell sandbox yet, so in Folders mode only the file tools work unless you allow an unconfined shell. Details are in [docs/windows.md](docs/windows.md).

## Self-signed certificates

The portal needs TLS, and a self-signed certificate is fine. Plain HTTP works only when the portal runs on the same machine. The pairing URI carries a hash of the certificate's key, which the client pins. To compute it for `cert.pem`:

```sh
openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary | basenc --base64url | tr -d '='
```

## Build

Needs Rust (stable, 1.88 or newer).

```sh
cargo build --release -p pithagoras-sync                                       # for this machine
cargo build --release --target x86_64-unknown-linux-musl -p pithagoras-sync    # the static Linux release
cargo xwin build --release --target x86_64-pc-windows-msvc -p pithagoras-sync  # Windows, with cargo-xwin
```

## Test

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

The tests use temporary folders and a mock portal. They never touch your real config, systemd or a real portal. `scripts/windows-vm-test.sh <host>` runs the Windows tests on a Windows machine over ssh.

## Documentation

- [docs/protocol.md](docs/protocol.md): the wire protocol between portal and device, and the decisions still open.
- [docs/windows.md](docs/windows.md): how the Windows client differs, and what is unverified.

## Licence

Apache-2.0, see [LICENSE](LICENSE).

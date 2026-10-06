# Pithagoras Sync

Lets the agent of your [Pithagoras](https://github.com/thecodacus/pithagoras) portal reach your own computers, the way a file-sync client reaches the cloud: pair once, it starts with the machine, reconnects by itself, and from then on the agent can use that computer's files, shell and git when a chat is granted the device.

**Status: 0.0.1.** It is the background client without a GUI (phase 1); 0.1.0 is the release where all of phase 1 is done. The portal side is the Devices add-on of the portal (`thecodacus/pithagoras#87`, not merged yet); until it is, the client can be tried against a mock portal or a portal that runs that branch. The desktop app with overlay, voice and computer use is phase 2.

## Platforms

- **Linux** (x86_64; aarch64 from the release workflow, not tried on a machine yet): one static binary, for desktops and servers, started as a systemd user or system unit.
- **Windows** (x86_64): the same remote access, started by a logon task. Tested on one Windows machine; see [docs/windows.md](docs/windows.md) for what differs and what was not tested.

## What the portal may do

You decide on the device, never the portal:

- **Ask** (the default everywhere): every call asks for your approval. The question shows up in the portal's Devices tab, where you answer Allow once, Allow for this chat, Allow for a time, or Deny (the last two only for reads and writes: a command asks each time); or on the device with `pithagoras-sync approvals`, `approve <id>` and `deny <id>`. Nobody answering within 2 minutes is a denial.
- **Folders**: files only inside the folders you grant, read-only unless you add `--rw`; commands only in folders you grant `--exec`. Commands run under Landlock (Linux 5.13 or newer) and can write only inside your read-write folders; without Landlock each command asks.
- **Full**: everything your user can do. It falls back after 8 hours by default. Protected paths (`~/.ssh`, keyrings, browser profiles, shell start-up files and more) and prompts for risky commands stay on unless you turn them off.

Every other permission is a setting too: which pi tools the device serves, paths and commands to deny, hours, approval timeouts, whether the client may run as root, whether `sudo` commands may run, and whether the portal may only read these settings (the default), change them, or not see them at all. `pithagoras-sync config get` shows them, `config set <name> <value>` changes one; [docs/permissions.md](docs/permissions.md) lists them all.

`pithagoras-sync panic` stops everything at once: it closes the link and kills every command until you run `pithagoras-sync unlock`. Every decision goes to a local audit log, `~/.local/state/pithagoras-sync/audit.jsonl`, and every settings change with its old and new value.

## Linux laptop or desktop

1. Download the binary and make it executable (`pithagoras-sync-aarch64-linux` on ARM). Releases are published by a version tag ([docs/releasing.md](docs/releasing.md)); to build it yourself, see below.

   ```sh
   curl -LO https://github.com/Piggidragon/Pithagoras-Sync/releases/download/v0.0.1/pithagoras-sync-x86_64-linux
   chmod +x pithagoras-sync-x86_64-linux
   ```

2. Install it. This copies the program to `~/.local/bin/pithagoras-sync` and starts it now and at every login, as a systemd user unit. Until it is paired the client just waits (`status` says "not paired"). You do not start it yourself: `pithagoras-sync run`, which the unit runs, is only for starting it by hand in a terminal, to see its log while debugging.

   ```sh
   ./pithagoras-sync-x86_64-linux install
   ```

   `~/.local/bin` is on the `PATH` of most distributions once the folder exists and you log in again. Until then, in this terminal: `export PATH="$HOME/.local/bin:$PATH"`.

3. In the portal, open Settings, Devices, "Pair a device", and copy the pairing URI. Then pair. Quote the URI, since it contains `&`. On a desktop, this and every later policy change asks for your password in the terminal. The running client takes the pairing at once.

   ```sh
   pithagoras-sync pair 'pithagoras-sync://pair?portal=...&code=...&spki=...'
   ```

4. Check that it runs. To use Folders mode, grant folders first:

   ```sh
   pithagoras-sync status
   pithagoras-sync folder add ~/src/myproject --rw --exec
   pithagoras-sync mode folders
   ```

`pithagoras-sync install --print` shows what `install` would do without doing it; `pithagoras-sync uninstall` undoes it. `pithagoras-sync uninstall --purge` also removes everything else the client left: it stops the running client, then removes the pairing (remove the device in the portal as well), the config with its folders and policy, the token, a stored elevation password, the audit log, the client's log and the update records. Only files the client writes, inside its own folders, go; anything else there stays. It lists what it removes and asks first (`--yes` does not ask, `--print` only lists). The program itself stays, and `--purge` says where it is so you can delete it. With `sudo … uninstall --system --purge` it removes the system unit and root's own files; a dedicated user and its files go with `setup --remove`.

## Linux server

Run the client as an unprivileged user, ideally a dedicated one. The client refuses to run as root unless you allow it (`policy.privilege.allow_root`, off by default); Proxmox containers run as root by default, so there `pithagoras-sync config set policy.privilege.allow_root true` lets it start, and the agent then acts with root's rights wherever the policy lets it.

```sh
sudo ./pithagoras-sync-x86_64-linux setup --create-user   # shows what it creates and asks first
sudo setfacl -R -m u:pithagoras-sync:rwX /srv/project
sudo -H -u pithagoras-sync pithagoras-sync folder add /srv/project --rw --exec
sudo -H -u pithagoras-sync pithagoras-sync mode folders
sudo -H -u pithagoras-sync pithagoras-sync pair '<uri from the portal>'
sudo systemctl start pithagoras-sync
```

`setfacl` comes with the `acl` package, which Debian and Ubuntu leave out (`sudo apt install acl`); `setup` says so when it is missing, and `sudo chown -R pithagoras-sync: /srv/project` works instead where the project need not stay another user's. `setup --create-user` creates the user with a locked password and installs the program to `/usr/local/bin` with a system unit, enabled but not started until you pair (`pair` then names the `systemctl start`); `sudo pithagoras-sync setup --remove` undoes it. For an existing user, use `sudo pithagoras-sync install --system --user <name>`; as your own user without root, use `pithagoras-sync install`, which turns on lingering so the unit runs without a login. Approvals work on a server as anywhere else, through the portal or `pithagoras-sync approve` over ssh.

## Windows

Download `pithagoras-sync-x86_64-windows.exe` from the [release page](https://github.com/Piggidragon/Pithagoras-Sync/releases/tag/v0.0.1), save it as `pithagoras-sync.exe`, then in PowerShell:

```powershell
.\pithagoras-sync.exe install
.\pithagoras-sync.exe pair 'pithagoras-sync://pair?portal=...&code=...'
```

`install` copies it to `%LOCALAPPDATA%\Programs\pithagoras-sync` and adds a logon task that starts it at logon and again within a minute if it stops; it needs no admin rights. The task runs the client without elevation, even when `install` ran in an elevated PowerShell; started by hand in an elevated one, the client refuses to run unless you allow it. Until it is paired the client waits, and `pair` makes it connect at once. You never start it yourself (`pithagoras-sync run` is only for running it by hand in a terminal, for debugging). The installed copy is not on the `PATH`; the downloaded file does the same for every later command (`.\pithagoras-sync.exe status`). Commands run in PowerShell. Windows has no shell sandbox yet, so in Folders mode every command asks unless you allow an unconfined shell, and `sudo` commands are Linux only (`pithagoras-sync sudo` says so). Each time the task starts the client (at logon, and again after a stop or an update) a console window can flash for a fraction of a second; a launcher without console comes with the graphical install (issue #6). Details are in [docs/windows.md](docs/windows.md).

## Commands as root (sudo)

On Linux, the agent can run `sudo <command>` if you allow it and type your password on the device, never in the portal:

```sh
pithagoras-sync sudo set       # type the password (not echoed), then answer "activate now?"
pithagoras-sync sudo status    # active or not, password set or not, and the next step
pithagoras-sync sudo deactivate    # sudo access off again; the password stays
pithagoras-sync sudo clear     # forget the password
```

`sudo activate` switches sudo access on later (it offers to store a password first if there is none). In a script, `sudo set --stdin --activate` reads the password from stdin and switches it on without asking. `pithagoras-sync sudo --help` lists everything.

The device hands the password to sudo itself; the agent never sees it, and it is scrubbed from command output, the audit log and everything sent to the portal. It stays in the running client's memory unless you choose `policy.privilege.secret_storage file`. Every `sudo` command asks for your approval, in every mode. A client that already runs as root (an LXC, say) has nothing to elevate, so its `sudo` is an ordinary command that does not ask. Details in [docs/permissions.md](docs/permissions.md).

## Updates

```sh
pithagoras-sync update --check
pithagoras-sync update
```

`update` takes a newer release only if its manifest carries a valid signature by the release key built into the program and it was not released before one the client already took, checks the download's size and sha256 and that it runs and reports the promised version, replaces the program in one step and restarts the client. It replaces the program the running client was started from (the installed copy its unit or logon task starts), whichever copy you run `update` from, and says so when that is not the one you ran; with no client running it replaces the one you ran and names the installed copy if that is another. Whether a release is newer is decided by the version of the program it replaces, as that file is on disk; when that is current but the running client is older (after `install` ran again from a newer download, say), `update` restarts the client instead. Your config and policy stay as they are.

A server set up with `setup --create-user` or `install --system` has its program in `/usr/local/bin`, owned by root, so its own user cannot replace it (`update` says so). Update it as root:

```sh
sudo pithagoras-sync update
```

As root, `update` replaces the program the system unit starts, even when root also runs a client of its own from elsewhere (and only if that file, every folder above it and every folder that holds a link on the way belong to root and are writable by nobody else, since root runs it; `setup` and `install --system` warn at once when that is not so, with the fix), and restarts the unit if it runs (also when the program is current but the unit still runs an older copy of it). A release is refused if it was made before the newest one seen for that program or the newest one this user installed for any program, so an older release served again is not taken, not even by a program updated for the first time. Updates come from the newest GitHub release of this repository (a test pre-release such as `pre-v0.0.2` is not "newest": take it with `pithagoras-sync update --manifest https://github.com/Piggidragon/Pithagoras-Sync/releases/download/pre-v0.0.2/manifest.json`); a build of your own has no release key and says so. How releases are made: [docs/releasing.md](docs/releasing.md).

## Self-signed certificates

The portal needs TLS, and a self-signed certificate is fine. Plain HTTP works only when the portal runs on the same machine, and it trusts whoever answers on the portal's port: any local account can listen on a free port (while the portal restarts, say). So the client takes only the IPv4 address of a name like `localhost` (the portal listens on IPv4, which would leave `[::1]` on its port to anyone), and on Linux it sends nothing unless the connection's socket and every socket listening where it could have arrived belong to the client's user or root (the listeners count because Linux 6.16 and older list a connection the program has not accepted yet as root's). A portal in a container whose port is forwarded by NAT rather than by a proxy process cannot be told apart that way and needs https too. On Windows there is no such check: on a machine shared with other accounts, and wherever the portal runs as another user, use https. The pairing URI carries a hash of the certificate's key, which the client pins. To compute it for `cert.pem`:

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

The musl build compiles ring's C parts and needs a C compiler for musl: `musl-gcc` (Debian's `musl-tools`), or clang with `CC_x86_64_unknown_linux_musl=clang`.

## Test

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

The tests use temporary folders and a mock portal. They never touch your real config, systemd or a real portal. `scripts/windows-vm-test.sh <host>` runs the Windows tests on a Windows machine over ssh.

## Documentation

- [docs/permissions.md](docs/permissions.md): every setting, its default, and who may change it.
- [docs/protocol.md](docs/protocol.md): the wire protocol between portal and device, and the decisions still open.
- [docs/testing.md](docs/testing.md): the tests, the tools for trying a client by hand, and the record of the test machine.
- [docs/windows.md](docs/windows.md): how the Windows client differs, what was tested and what was not.
- [docs/releasing.md](docs/releasing.md): the release workflow, the release key and its one-time setup.

## Licence

Apache-2.0, see [LICENSE](LICENSE).

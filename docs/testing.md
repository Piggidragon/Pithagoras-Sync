# Testing

## Automated tests

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

They use temp dirs, fake roots, fake `sudo` scripts and the mock portal in `crates/testkit`; they never touch the real config, systemd, the user's notification service, a real keyring, the registry or a real portal. `crates/pithagoras-sync/tests/e2e.rs` runs the real binary against the mock portal, `tests/update.rs` runs the updater against releases in temp dirs and on a loopback HTTP server. The Windows tests run on a Windows machine with `scripts/windows-vm-test.sh <host>`.

## Tools for trying a real client by hand

Two programs in `crates/testkit` (built with `cargo build -p sync-testkit --bins`):

- `sync-mock-portal [port]`: the mock portal on loopback. It prints `portal http://127.0.0.1:<port>`, then reads one command per line from stdin (`code <CODE>`, `wait`, `exec <cwd> <command>`, `approve once|deny|none`, `call <method> <json>`, `read <path>`, `close`, `closed`, `sleep`, `grep <text>`, `dump <file>`, `quit`; the source lists them). To drive it from another shell, feed it a file: `tail -f mock.cmds | sync-mock-portal 18080`, then `echo 'code ABC123' >> mock.cmds`.
- `sync-test-sign keygen <keyfile>` writes a throwaway key (the same format as `sync-release`, docs/releasing.md) and prints its public key; `sync-test-sign sign <keyfile> <file>` writes `<file>.minisig` in minisign's format.

A build that can update itself needs a release key compiled in:

```sh
pub=$(sync-test-sign keygen test.key)
PITHAGORAS_SYNC_UPDATE_KEY="$pub" cargo build --release -p pithagoras-sync
```

`PITHAGORAS_SYNC_UPDATE_URL` sets the default manifest URL the same way (without it, the default is the stable release channel on GitHub); `update --manifest <url or file>` names another. A release folder holds `manifest.json`, which `sync-release manifest --version 0.1.1 --out manifest.json pithagoras-sync-x86_64-linux=x86_64-linux` writes (docs/releasing.md):

```json
{"version": "0.1.1", "released": 1791244800, "artifacts": {"x86_64-linux": {"url": "pithagoras-sync-x86_64-linux", "size": 11206656, "sha256": "<hex>"}}}
```

next to `manifest.json.minisig` (`sync-test-sign sign test.key manifest.json`) and the binary. `url` is relative to the manifest or absolute. `released` is the time the manifest was made (Unix seconds, now unless `--released` names one); a client refuses a manifest released before the newest one it saw for that program (`~/.local/state/pithagoras-sync/update-released-<hash of the program's path>`) or the newest one this user installed (`update-released` beside it), with `update --check` as well, so a test folder made again needs a later time, or those files removed. `pithagoras-sync uninstall --purge --yes` removes them together with the rest of the client's files (config, pairing, logs) and leaves the program, so a test machine starts afresh between versions; run it as each user that ran the client, and with `sudo … uninstall --system --purge --yes` for root and the system unit.

## The graphical flow and the keyring without a desktop

The tests never show a window or touch a keyring: the flow (`gui.rs`) runs against fake dialogs and a fake host, the dialog programs' arguments are checked as built, `tests/e2e.rs` runs the real binary with stand-in `zenity`/`kdialog` scripts on `PATH`, and the Secret Service code runs against a fake service of the testkit (`sync_testkit::keyring`) on a private `dbus-daemon`. To try them by hand on a machine without a display:

- **A fake dialog program.** The client takes a dialog program only from a folder root alone can change (permissions.md, "The graphical flow"). A debug build also takes the ones in the folder `PITHAGORAS_SYNC_TEST_DIALOG_DIR` names; a release build ignores that variable. Put a script named `zenity` (or `kdialog`) there and first on `PATH` that prints its arguments and answers, and run the debug build with any `DISPLAY` set:

  ```sh
  mkdir -p /tmp/fakegui && cat > /tmp/fakegui/zenity <<'SH'
  #!/bin/sh
  printf '%s\n' "$@" >&2      # what the dialog would show
  exit 0                     # 0: Yes/OK; 1: No/Cancel. An --entry or --list answer goes to stdout.
  SH
  chmod +x /tmp/fakegui/zenity
  DISPLAY=:99 PATH=/tmp/fakegui:$PATH PITHAGORAS_SYNC_TEST_DIALOG_DIR=/tmp/fakegui \
    target/debug/pithagoras-sync 'pithagoras-sync://pair?portal=http://127.0.0.1:18080&code=ABC123'
  ```

  With the mock portal (`sync-mock-portal 18080`, then `code ABC123`) this pairs after the stand-in's "Yes". `tests/e2e.rs` (`fake_dialogs`) has a stand-in that answers from a file, line by line; its harness sets the variable to the test's own `fakebin`, so the e2e tests of the windows need the debug build (`cargo test`, not `cargo test --release`).
- **Real zenity in a user namespace.** `unshare --user --map-user=1000` shows root's files as owned by `nobody`, so there the client takes no dialog program, not even `/usr/bin/zenity`, and `gui` says it cannot show its windows. Try the real one as a normal user outside such a namespace.
- **Real zenity under Xvfb.** With `xvfb`, `zenity` and `xdotool` installed: `xvfb-run -a pithagoras-sync gui &`, then `xdotool search --name 'Pithagoras Sync'` finds the window and `xdotool key Return` answers its default button (Yes, OK, the first row of the menu). `import -window root shot.png` (ImageMagick) shows what is on the screen. Without a window manager the keys go to the window under the pointer (`xdotool mousemove 200 200` first); in the menu's list, typing filters it, and clicks need a pause between `mousemove` and `click`. The container has no German locale installed, so `LANG=de_DE.UTF-8` shows the German texts with English buttons (the client then gives the dialog program `LC_ALL=C.UTF-8`, see permissions.md).
- **A real keyring, headless.** With `dbus`, `gnome-keyring` and `libsecret-tools`:

  ```sh
  dbus-run-session -- sh -c 'echo "" | gnome-keyring-daemon --unlock --components=secrets; \
    pithagoras-sync config set token_storage keyring; pithagoras-sync pair "<link>"; \
    secret-tool lookup application pithagoras-sync name token'
  ```

  Locked again (`gdbus call --session --dest org.freedesktop.secrets --object-path /org/freedesktop/secrets --method org.freedesktop.Secret.Service.Lock "['/org/freedesktop/secrets/collection/login']"`), GNOME Keyring wants its unlock prompt, which needs a display: without one the prompt counts as cancelled and the client says so.
- **The link handler.** `install` from a session with `DISPLAY` set (a stand-in `systemctl` on `PATH` keeps the real systemd out; `XDG_DATA_HOME` and `HOME` pointed into a temporary folder keep the real `~/.local` out), then `xdg-mime query default x-scheme-handler/pithagoras-sync` says `pithagoras-sync.desktop`, and under Xvfb `gio open 'pithagoras-sync://pair?...'` starts `pithagoras-sync gui <link>`. `xdg-open` without a desktop environment (its "generic" mode) did not open the link on the build machine; on GNOME and KDE it hands it to `gio` or `kde-open`.

`PITHAGORAS_SYNC_NO_KEYRING=1` makes the client use no keyring at all. The test harnesses (`tests/e2e.rs`, `tests/update.rs`, `tests/e2e_windows.rs`) set it for every run of the client, so a test never reaches the real session bus or the machine's Credential Manager; only the tests that start the testkit's fake Secret Service on a private bus leave it out and point `DBUS_SESSION_BUS_ADDRESS` at that bus. A new e2e test that wants a keyring does the same.

## Linux evidence for 0.0.2 (the build machine, headless)

Run on 2026-10-06 in a cloud container (Ubuntu 24.04, no desktop, no systemd user manager, no IPv6), as an unprivileged user in a user namespace (`unshare --user --map-user=1000`), with the debug build. No real portal and no machine of the owner's was touched.

- **GNOME Keyring 46 through the Secret Service**, on a private session bus: `config set token_storage keyring`, then `pair` against the mock portal put the 43-byte token in the keyring (`secret-tool lookup application pithagoras-sync name token`) and no `token` file in the config folder; `status` said "token kept in the keyring". `config set token_storage file` wrote the file and removed the keyring entry; `keyring` moved it back. `secret_storage = keyring` with `sudo set --stdin` stored the password there (`secret-tool` showed it), `sudo status` said "set (kept in keyring)", `sudo clear` and `unpair` removed the entries. The running client connected with the token from the keyring. With the login collection locked over D-Bus and no display for GNOME Keyring's prompter, `pair` failed with "cannot keep the token in the keyring (token_storage = keyring): the keyring stayed locked: the keyring prompt was cancelled", wrote no token file, and the running client stayed connected with its old token.
- **zenity 4 under Xvfb**, answered with `xdotool`: the pairing question (screenshot: the parsed portal URL and device name, No and Yes), the info after pairing ("Installed, not connected yet: the client is not running", since no client ran in that test), the entry for a pasted link, the menu of a paired device with all five items, and the status text. Each answer did what the flow says; the pasted link paired.
- **German, and the sudo password's field** (zenity 4.0.1 under Xvfb, `LANG=de_DE.UTF-8`, a locale this machine does not have): before the locale fix zenity refused every text with an umlaut ("This option is not available") and showed nothing, so a German question would have read as No; `LANG=C` did the same to any non-ASCII text, English ones too. With it, `pithagoras-sync gui` showed the German menu (Status, Neu koppeln, Sudo-Zugriff, Protokoll öffnen, Deinstallieren, Schließen) and the German status ("Client: läuft nicht", "Modus: ask: Jeder Dateizugriff …", "Sudo-Zugriff: ausgeschaltet"). `zenity --entry --hide-text` with the German prompt showed eight dots for `geheim 1` and printed `geheim 1` and a newline on stdout. The whole sudo flow through the windows was not driven under Xvfb (the list did not take synthetic clicks reliably); `tests/e2e.rs` runs it with stand-in dialogs and a stand-in sudo against the real client. A real `sudo` checking a real password was not tried: the container allowed no throwaway user with a sudoers entry.
- **The link handler**: `install` with `DISPLAY` set wrote the desktop entry and the icon and ran the real `update-desktop-database` and `xdg-mime`; `xdg-mime query default x-scheme-handler/pithagoras-sync` said `pithagoras-sync.desktop`, the `mimeinfo.cache` had the line, `desktop-file-validate` found the entry valid, and `gio open` on a pairing link started `~/.local/bin/pithagoras-sync gui <link>`, which asked before pairing. `uninstall` removed the entry and the icon.
- **Windows**: cross-built and linted for `x86_64-pc-windows-gnu` only (`cargo clippy --workspace --target x86_64-pc-windows-gnu --all-targets -- -D warnings`), since `cargo xwin` could not fetch the MSVC SDK there. Nothing ran on Windows there; see [Windows](#windows) for the later runs on the test VM.
- `connector::net::tests::plain_http_reaches_this_users_portal_in_either_address_family` fails on that machine, before these changes too: it has no IPv6.

## The test machine

A test container, Ubuntu 24.04 (Proxmox kernel 7.0, systemd 255; no Landlock in its LSM list, so Folders mode asks for every command there). The client, the mock portal and `sync-test-sign` were musl release builds copied to `/opt/pst`, built with `PITHAGORAS_SYNC_UPDATE_KEY` set to a throwaway test key; a second build with the version bumped to 0.1.1 served as the update. The mock portal ran on the container itself (port 18080), driven through a command file as above. Nothing here touched another machine or a real portal. Run on 2026-10-05, phase 1b.

### Dedicated user with a system unit

```sh
pithagoras-sync setup --create-user --yes
sudo -H -u pithagoras-sync pithagoras-sync pair '<uri from the mock>'
sudo -H -u pithagoras-sync pithagoras-sync folder add /srv/proj --rw --exec
sudo -H -u pithagoras-sync pithagoras-sync mode folders
systemctl start pithagoras-sync
```

- `setup` created the locked user `pithagoras-sync`, the program in `/usr/local/bin` and the system unit.
- `exec` in `/srv/proj` asked ("the kernel has no Landlock, so every command asks"); approved, it ran in its own cgroup, `/system.slice/pithagoras-sync.service/pithagoras-exec-<pid>-1`. A working folder outside the grant was denied.
- `panic` closed the link and killed a `setsid` child of a running command; `unlock` reconnected. The mock's `close` was followed by a reconnect.
- `policy.set` from the mock was `DENIED` under the default `portal_policy = read`.
- `mode full`: commands in `/tmp` ran without asking.
- `setup --remove --yes` removed the user and the unit; `/usr/local/bin/pithagoras-sync` stays, as documented.

### Elevation with real sudo

Run before the `sudo` command group replaced the `secret` commands and the elevation setting; the commands below are today's names for what was run (`sudo set --stdin --activate` was `config set policy.privilege.elevation sudo` and `secret set elevation --stdin`, `sudo status` was `secret status`).

A user `elevtest` with a password containing a quote and a backslash, in sudoers with `ALL=(ALL:ALL) ALL`. Lingering was enabled by root (the user's own `loginctl enable-linger` was refused by polkit, and `install` printed the hint for it).

```sh
pithagoras-sync install                                  # user unit
pithagoras-sync pair '<uri>'
pithagoras-sync mode full
printf '%s\n' "$PW" | pithagoras-sync sudo set --stdin --activate
```

Results, each command approved through the mock portal:

- `sudo id -u` printed `0`.
- As root, the elevated command wrote its environment, its stdin (0 bytes), `ps` output (35 lines), every `/proc/*/cmdline` and every `/proc/*/environ` to files: none contained the password. A root watcher reading `/proc/*/cmdline` and `environ` in a loop with `grep -F -f` during the run found nothing.
- `cat /root/pw.txt` (a file holding the password): permission denied. `sudo cat /root/pw.txt`: the output reached the portal as `[redacted]`.
- `sudo -u nobody id`: refused (sudo's own options are not taken).
- The client's `/proc/<pid>/environ` belongs to root:root (the client is undumpable), so the user's other processes cannot read its memory.
- With `strace` attached to the client: the exec shim refused to take the password (exit 126) and `sudo set` was refused ("being traced").
- A wrong stored password: sudo answered "Sorry, try again" and "1 incorrect password attempt", exit 1.
- After `panic`, `sudo status` showed `Password:    not set` (`secret status` said "no password set" then).
- The audit log, the user's journal, the full system journal and the mock portal's transcript of everything the device sent (`dump`) held the password neither as it is nor JSON-escaped.
- `secret_storage = file`: `~/.config/pithagoras-sync/elevation.secret` was 0600 and the password worked after a restart of the client. `fs.read` of the file was denied (sealed). An unconfined Full-mode `cat` of it was readable, its output `[redacted]`: the known limit of file storage. `sudo clear` removed the file.

### Update

As `elevtest`, against a local release folder with 0.1.1:

- `update --check` reported 0.1.1.
- `update` replaced `~/.local/bin/pithagoras-sync`; the client exited with 75 and systemd started it again as 0.1.1. The config file was byte for byte the same (`cmp`).
- `update` again: "Up to date".
- A manifest changed after signing: refused, the signature does not verify, exit 1.

### Root

```sh
pithagoras-sync config set policy.privilege.allow_root true   # without it, install --system refuses
pithagoras-sync install --system
```

`id -u` through the portal printed `0`, the command ran in its own cgroup, `panic` killed a `setsid` child and `unlock` reconnected. The journal warns "running as root".

### Ask and the portal's write access

- With `policy.approvals.timeout_secs = 5` and no answer: "no answer to the approval within 5s", audited.
- With `portal_policy = write`: `policy.set` switched `policy.tools.bash` off, audited as `by the portal: true -> false`.

### Cleanup

The units were uninstalled, `elevtest` and its sudoers file removed, the mock stopped, and `/opt/pst`, root's test files and configs deleted.

## Windows

A Windows test VM (Windows 10.0.26300, Windows PowerShell 5.1, no `pwsh`, OpenSSH server, an administrator account, so every ssh session was elevated). Nothing was installed on it: no Rust, no build tools. Everything was cross-built on Linux with `cargo-xwin` and copied over. Run on 2026-10-05, phase 1.

### The test suite

```sh
scripts/windows-vm-test.sh <user>@<windows host>
```

The purge test runs completely only from a normal (not elevated) process: from an administrator's ssh session, which is always elevated, it checks that the purge refuses and changes nothing, then stops. Run it once from a scheduled task of a normal user (or any Medium-integrity process) to cover the rest.

It builds the client and every test program for `x86_64-pc-windows-msvc`, copies them to a fresh folder in the user's home, runs each there and removes the folder. All 19 test programs passed. The Windows-only ones:

- `crates/ops/tests/files_windows.rs`: a junction swapped in under a granted folder fails read, stat, write and list, and the file outside is not truncated; short names and case reach the same file.
- `crates/ops/tests/exec.rs`: PowerShell output is plain UTF-8 text (no CLIXML, no OEM code page), the command has no console window, the exit code arrives.
- `crates/pithagoras-sync/tests/e2e_windows.rs`: the real client against the mock portal: refused when elevated until `allow_root`, the control pipe's security, Folders mode prompting, the file tools, an unconfined shell, `panic` and a killed client both ending a `Start-Process` child, `unlock`.
- `crates/pithagoras-sync/tests/update_windows.rs`: a release from a `C:\` manifest path replaces a running program, which goes aside to `.old`.

Found this way and fixed: the program needed `VCRUNTIME140.dll`, which a fresh Windows lacks (it now links the C runtime statically, `.cargo/config.toml`; the script refuses a build that imports it); every config failed validation on Windows (`sudo_path` judged as a Windows path); a junction swapped in after the check could empty a file outside the folder; PowerShell errors arrived as CLIXML and non-ASCII output in code page 850; the protected-path check missed `\` and the PowerShell home variables; `update` looked for a local release's binary in the working directory.

### By hand, against the mock portal

The client ran with its own profile (`USERPROFILE`, `APPDATA` and `LOCALAPPDATA` pointed to a test folder), the mock portal ran on the Linux machine, and the VM reached it through `ssh -N -R 18080:127.0.0.1:18080 <vm>`, so the portal URL was `http://127.0.0.1:18080` there.

- Paths sent as the portal sends them: case-insensitive matches, an 8.3 name and `sub/../a.txt` inside the folder worked. `C:\`, `c:/`, `//localhost/c$`, `//?/C:`, `a.txt:hidden`, `a.txt::$DATA`, `CON`, `nul.txt` and a trailing dot were `BAD_PATH`; paths outside the folder, a junction and a symlink to outside were `DENIED`; a symlink to `\\localhost\c$` was `BAD_PATH`.
- Commands: Folders mode asked for each; approved, they ran. Timeout, `exec.signal`, the mock's `close` and `panic` each ended a hidden `Start-Process` child. The mock's `close` was followed by a reconnect within a second; `panic` closed the link with 1000 and `unlock` reconnected.
- A process started through WMI (`Win32_Process.Create`) survived `panic`: the job does not reach it.
- With `folders_shell = "unconfined"`, a command read `~\.ssh\id_ed25519` and wrote outside the folder once approved: Folders mode does not confine commands on Windows.
- The control pipe: before the fix, a Low-integrity copy of PowerShell (`icacls /setintegritylevel low`) could connect for reading and held every instance, so `panic` failed with "all pipe instances are busy". After it, that process was refused in every direction. A second Windows user was not available, so another account was not tried.

### Start at logon

`pithagoras-sync install` (the real task name, "Pithagoras Sync"; there was none before):

- The task was created and started; the client ran in the user's session (2), at Medium integrity, without a console window, and the CLI in the elevated ssh session reached it over the pipe.
- `install` again while it ran: it ended the task's client, replaced the program (the running copy went to `.old`) and started it again.
- Killed with `taskkill /f`, the client stayed down with Task Scheduler's restart on failure alone (more than 2 minutes); with the minute trigger it was back after 10 seconds.
- `uninstall` ended the client and deleted the task and its definition.
- Not tested: a real logoff and logon, since the VM offers no way to log on again without its password, and whether a console window flashes then.

### Second run: log file, known folders, release builds

Run on 2026-10-05 after the log file, the known folders and the release tooling came in: `scripts/windows-vm-test.sh` again, 21 test programs, all passed. New among them: the protected paths ask Windows for Documents and `System32` (`KnownFolders`) and protect what is in them; the capped log file moves aside at its cap; `sync-release` signs and verifies.

By hand, from the elevated ssh session: `run --detach` with a fresh config refused the elevated session (exit 1), and that refusal was the line in `%LOCALAPPDATA%\pithagoras-sync\client.log` (here under `PITHAGORAS_SYNC_CONFIG_DIR`), plain text. The test folder was removed afterwards.

Not done in this run: a second local account for the control pipe's ACL, and a command sandbox (restricted token or AppContainer) with a check of processes started through WMI, scheduled tasks or COM; see windows.md.

### Third run: the graphical install

Run on 2026-10-07 with the release build, as a standard user logged on at the console (Medium integrity), driven through UI Automation with real mouse double clicks in Explorer, against the mock portal on loopback. A watcher logged every window shown in the session.

- 44 installs and uninstalls from the window in German (30 with Windows Terminal as default terminal, 14 with the classic console) and 32 in English, each one: double click the download, install, paste the link, pair, "connected", then double click the installed program, menu, uninstall, with and without removing the settings. None failed. Before the fix, 6 of 18 installs and 5 of 8 uninstalls had failed ("The request is not supported", from stale console handles).
- A pairing link opened from Edge (after its "Open" prompt) and with `Start-Process` reached the installed program as `pithagoras-sync://pair/?…` and asked the replace question; Yes paired again, No changed nothing.
- No text, an image or 5000 characters in the clipboard at the paste box each gave a box and then the paste box again; the last menu box says "No or Cancel: close"; a purge that could not remove a locked `config.toml` showed its lines as lines; `uninstall` twice exited 0 both times.
- Console windows: none from the programs the window starts; the program's own console at each double click, link or start by the task showed for a median 0.21 s as a Windows Terminal window, or 23 ms as a classic console (issue #6).
- Not tried: Windows 10, Chrome, Firefox, a real download from GitHub (SmartScreen was shown with a `Zone.Identifier` copy), a real portal.

### Cleanup

The task was deleted, the client stopped, and the test folders, the client's folders under `%APPDATA%` and `%LOCALAPPDATA%` and the installed program removed from the VM.

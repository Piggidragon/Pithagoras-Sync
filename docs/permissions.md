# Permissions and settings

Everything the portal's agent may do on a device is decided on the device, in its config file (`~/.config/pithagoras-sync/config.toml` on Linux, `%APPDATA%\pithagoras-sync\config.toml` on Windows). This page lists every setting: its name, values, default, what it does, how to change it, and whether the portal may change it.

The defaults are the safe side: Ask mode, approvals that time out to a denial, no elevation, the client not running as root, and the portal allowed to read the settings but not to change them.

## Changing settings

Every setting can be changed in three ways:

- **CLI**: `pithagoras-sync config set <name> <value>`, with the dotted names below. Values are JSON where they parse as JSON (`true`, `8`, `["a"]`, `{"path": "~/x"}`), text otherwise. `config get [<name>]` prints one setting or all, `config unset <name>` puts one back to its default, `config add <name> <value>` and `config remove <name> <value>` add an entry to a list or take every equal entry out. The common ones have their own commands (`mode`, `folder`, below).
- **The file**: edit `config.toml` by hand. Unknown names and bad values are refused; the client keeps its old settings until the file is right.
- **The portal**: the Devices tab, only where the owner set `portal_policy = "write"` (see the last column), through `policy.set` (protocol.md, section 7).

Each change takes effect at once in the running client and is written to the audit log with the setting's old and new value (`by the device owner: false -> true`, or `by the portal: ...`). A running portal connection hears of it with `policy.changed`.

Who may change them on the device:

- Only the device's own user (the account the client runs as). On a Linux desktop (`profile = "desktop"`) every change also asks for that user's password in the terminal, through `su`.
- On Linux, a change through the CLI from a command the client runs for the portal (a process descending from the client) is refused, whatever the command: `config`, `mode`, `folder`, `sudo`, `approve`, `deny`, `unlock`, `update`. Windows has no such check yet (windows.md).
- That check is not a wall around the policy. A command that runs unconfined has all of the user's rights: it can edit `config.toml` itself and make the client read it (`SIGHUP` reloads the config, and a client killed by the command is started again by its unit). Unconfined are a command you approved in Ask mode, every command in Full mode, and Folders mode's shell with `folders_shell = "unconfined"` or without Landlock after its approval. Only a command confined by Landlock (Folders mode) cannot reach the config, since the client's own folders are protected. So approving a command means trusting it with your account, the policy included.

## The settings

"Portal" says whether `policy.set` may change the setting when `portal_policy = "write"`: **yes**, **no** (device only: in the document the portal reads, listed under `device_only`), or **never** (not in the portal's document at all).

### Top level

| Setting | Values | Default | What it does | CLI | Portal |
|---|---|---|---|---|---|
| `profile` | `headless`, `desktop` | detected (`desktop` when a graphical session runs) | `desktop` makes every policy change ask for the user's password and allows desktop notifications for approvals. Takes effect after a restart of the client. | `config set profile desktop` | never |
| `portal_policy` | `off`, `read`, `write` | `read` | What the portal may do with these settings. `off`: it neither sees nor changes them (`hello` does not announce `policy`). `read`: the Devices tab shows them. `write`: the owner's portal session may change everything marked "yes" below, widening included (Full mode, folders, tools). | `config set portal_policy write` | never |
| `portal` | | | The pairing: portal URL, pin, device id and name. | `pair`, `unpair` | never |
| `token_storage` | `file`, `keyring`, or unset | unset: `file` on Linux, `keyring` on Windows | Where the connector token is kept. `file`: `token`, a 0600 file in the config folder. `keyring`: the OS keyring, the Secret Service on Linux (GNOME Keyring, KWallet, KeePassXC) or the Credential Manager on Windows (`cmdkey /list` shows `pithagoras-sync/token`). Changing it moves the token: it is written to the new place first, then the setting is saved, then the old place loses it. Unset on Windows, a keyring that fails at `pair` keeps the token in the file instead and says so once; an existing token file keeps working. Set to `keyring`, it never falls back: no keyring service, a locked keyring or a cancelled unlock prompt is an error (`pair` fails, the client cannot connect and `status` says why). `unpair` and `uninstall --purge` remove the keyring entry too. See "The keyring" below. | `config set token_storage keyring`, `config set token_storage file`, `config unset token_storage` | never |

### Modes: `policy.mode` and `policy.full`

| Setting | Values | Default | What it does | CLI | Portal |
|---|---|---|---|---|---|
| `policy.mode` | `ask`, `folders`, `full` | `ask` | **Ask**: every call asks for approval. **Folders**: file calls inside the granted folders only, commands only where a folder grants `execute`. **Full**: everything the user can do, with the protections below still on. | `mode ask\|folders\|full` | yes |
| `policy.full.expiry_hours` | hours, `0` = never | `8` | How long Full lasts before the device falls back to Ask. | `mode full --expiry-hours 2` | yes |
| `policy.full.until_ms` | Unix ms or none | none | When the current Full mode ends; set by the device when Full is switched on. | set by `mode full` | no effect (the device dates it) |
| `policy.full.protected_paths` | `true`, `false` | `true` | Protected paths (below) ask in Full mode too. | `config set` | yes |
| `policy.full.pattern_prompts` | `true`, `false` | `true` | Risky commands ask in Full mode: `sudo`, `su`, `doas`, `pkexec` and the like, `git push`, a download piped into a shell, `rm -r` outside the working folder. A client that runs as root (Linux, an LXC for example) does not ask for `sudo`, `su`, `doas` or `pkexec`, which change nothing for it; the other patterns still ask. The same holds for the unconfined Folders shell. | `config set` | yes |
| `policy.full.taint_prompts` | `true`, `false` | `true` | Calls from a chat the portal marked as having seen untrusted content (`ctx.tainted`) ask in Full mode too. | `config set` | yes |

### Folders

| Setting | Values | Default | What it does | CLI | Portal |
|---|---|---|---|---|---|
| `policy.folders` | list of `{path, access, execute}` | empty | The folders Folders mode allows. `path` absolute; `access` `ro` or `rw`; `execute` lets commands run with that folder as their working folder. | `folder add <path> [--rw] [--exec]`, `folder remove <path>`, `folder list` | yes |
| `policy.folders_shell` | `landlock`, `prompt`, `unconfined` | `landlock` | How commands run in Folders mode. `landlock`: under Landlock (Linux 5.13+), writable only inside `rw` folders and a `TMPDIR` of its own (removed when the command and what it left running are gone), unable to read protected or denied paths; without kernel support, and always on Windows, every command asks instead. `prompt`: every command asks. `unconfined`: commands run with all of the user's rights, only the risky-command patterns ask. | `config set policy.folders_shell unconfined` | yes |
| `policy.allow_globs` | list of `{glob, access}` | empty | Files the file tools may reach in Folders mode outside the folders (`~/.config/app/*.toml`). Commands are not affected. | `config add policy.allow_globs '{"glob": "~/notes/*.md", "access": "ro"}'` | yes |

Files the agent creates belong to the user the client runs as. The units `install` and `setup` write set `UMask=0077`, so what the client and its commands create is private to that user (`0600` files, `0700` folders) unless the folder says otherwise: under a folder with a default ACL, as from `setup`'s next steps, the umask does not apply and new files take the default ACL instead, so add one for yourself too to keep write access to them (`sudo setfacl -R -d -m u:<you>:rwX /srv/project`). A project handed over with `chown` gets `0600` files that only the dedicated user reads. The umask stays strict so that what the agent writes is not readable by other local users unless you choose that (the client's own files, the token, the config and the audit log, are `0600` either way); to loosen it, `sudo systemctl edit pithagoras-sync` (`systemctl --user edit` for a user unit) with `[Service]` and `UMask=0022`, or a command sets its own (`umask 022; ...`).

### Everywhere: tools, denials, commands, hours

| Setting | Values | Default | What it does | CLI | Portal |
|---|---|---|---|---|---|
| `policy.tools.read`, `.write`, `.edit`, `.bash`, `.grep`, `.find`, `.ls` | `true`, `false` | all `true` | Switches one pi tool off on this device. The portal offers the device only to tools that are on (`device.info` `tools`); a call for a tool that is off is denied. | `config set policy.tools.bash false` | yes |
| `policy.deny` | list of `{path, rights}` | empty | Paths (and everything below) or globs refused in every mode. `rights` is any of `r`, `w`, `x` (default `rwx`). Plain paths are enforced for the file tools and, under Landlock, for commands; globs only for the file tools. | `config add policy.deny '{"path": "~/private"}'` | yes |
| `policy.commands.deny` | list of rules | empty | Commands containing a match are refused. | `config add policy.commands.deny '{"prefix": "rm -rf"}'` | yes |
| `policy.commands.allow` | list of rules | empty | When not empty, only simple commands matching one of these run at all. | `config add` | yes |
| `policy.commands.always_ask` | list of rules | empty | Commands containing a match ask, in every mode. | `config add` | yes |
| `policy.commands.never_ask` | list of rules | empty | Simple commands matching one skip the mode's, the patterns' and elevation's questions. Not the taint question, deny rules or Folders' limits. | `config add policy.commands.never_ask '{"exact": "cargo test"}'` | yes |
| `policy.hours` | `{days, from, to, utc_offset_minutes}` or none | none (always) | The hours the device serves calls; outside them everything is denied. `days` from `mon` to `sun` (empty: every day), `from` and `to` as `HH:MM`, local time unless `utc_offset_minutes` is given; a range past midnight counts for the day it starts. | `config set policy.hours '{"from": "08:00", "to": "18:00", "days": ["mon","tue","wed","thu","fri"]}'` | yes |

A command rule is exactly one of `{"exact": "..."}` (the whole command, spaces normalised), `{"prefix": "..."}`, `{"glob": "..."}` (`*` matches anything) or `{"regex": "..."}` (searched in the command; anchor with `^...$`). Deny and always-ask rules are checked against the whole command and against each part between separators from every word on (so `sudo rm` meets a rule about `rm`). A glob that does not start with `*` and a regex anchored at the start (`^` or `\A` outside a character class; `[^#]` does not anchor) must be tried at every word, which for a very long one-line command could take minutes. So one command's check against each list is cut off after 16 MiB scanned by such rules, or after a second whatever the rules: past that the command counts as matching, so a deny rule refuses it and an always-ask rule asks. The check runs beside the client's own work, so `panic` and `status` answer meanwhile. Command rules are a filter on the text the portal sends, not a sandbox: a determined command can be written to slip past them. Only Landlock confines the shell.

### Protected paths: `policy.protected`

Built in: `~/.ssh`, `~/.gnupg`, keyrings and password managers, credentials of cloud and developer tools (`~/.aws`, `~/.azure`, `~/.config/gcloud`, `~/.kube`, `~/.docker`, `~/.config/gh`, `~/.config/hub`, `~/.npmrc`, `~/.pypirc`, `~/.cargo/credentials.toml`, `~/.vault-token`, `~/.git-credentials`, `~/.netrc`), browser and mail profiles, shell start-up files (`~/.bashrc` and `~/.bashrc.d`, the zsh and fish files, `~/.profile`), autostart folders and systemd user units, the client's own folders and more; `crates/policy/src/protected.rs` has the whole list. Only writes ask for `~/.gitconfig`, `~/.config/git`, `~/.local/bin` (early in `PATH` on many systems, where a program could stand in for another) and `~/.local/share/applications` (a `.desktop` file runs its `Exec=` line when the app is opened). Writes into folders named in `tool_config` (anywhere in a path) ask as well. Protected paths ask in Ask and Folders mode, and in Full mode while `policy.full.protected_paths` is on.

| Setting | Values | Default | What it does | CLI | Portal |
|---|---|---|---|---|---|
| `policy.protected.extra` | list of paths | empty | More protected paths (absolute or `~/...`). | `config add policy.protected.extra '~/work/secrets'` | yes |
| `policy.protected.allow` | list of paths | empty | Built-in protected paths the owner releases by name. | `config add policy.protected.allow '~/.config/git'` | yes |
| `policy.protected.tool_config` | list of names | `.git`, `.envrc`, `.vscode`, `.idea` | Names that make writes below them ask. | `config add` | yes |

### Approvals: `policy.approvals`

Approvals are asked through the portal (the Devices tab and the chat show them, `approval.requested`) and can be answered there or on the device:

```sh
pithagoras-sync approvals                  # what waits, with ids
pithagoras-sync approve 12                 # this call once
pithagoras-sync approve 12 --chat          # and more of its kind from this chat
pithagoras-sync approve 12 --minutes 30    # the same, for 30 minutes
pithagoras-sync deny 12
```

The first answer wins. "Of its kind" means reads or writes from the same chat, and is offered only for Ask mode's own question about a read or a write; commands ask every time in Ask mode (a standing approval of the shell would cover any command), and so do protected paths, patterns, taint and elevated commands.

`approvals` and the desktop notifications show the command with the folder it runs in (resolved; the audit log records it too), the path, chat and preview with every control character as a visible escape (`\u{1b}`, `\n`), so text from the portal cannot move the cursor or redraw what you read; the further lines of a command come indented under its header, and `approvals` shows a write's whole preview (up to 2000 bytes, then how many bytes the write holds in all). Line and paragraph separators (U+2028, U+2029) are escaped too, and a notification counts a target's length as shown, escapes included. A notification whose command or path is too long to show whole offers only Deny: answer it with `approvals` or in the portal. A command or path over 64 KiB is too long to show anywhere, so it can only be denied (run such a script from a file instead).

| Setting | Values | Default | What it does | CLI | Portal |
|---|---|---|---|---|---|
| `policy.approvals.timeout_secs` | 1 to 3600 | `120` | How long a call waits for an answer. | `config set policy.approvals.timeout_secs 300` | yes |
| `policy.approvals.on_timeout` | `deny`, `allow` | `deny` | What an unanswered approval turns into. `allow` lets the call through once. | `config set` | yes |
| `policy.approvals.remember_minutes` | 0 to 10080 | `60` | How long an "allow for this chat" answer lasts; `0`: until the chat's grant ends. | `config set` | yes |
| `policy.approvals.max_minutes` | 0 to 10080 | `480` | The longest "allow for a time" answer the device takes. | `config set` | yes |
| `policy.approvals.desktop_notifications` | `true`, `false` | `false` | Also show approvals as desktop notifications with Allow once and Deny (Linux desktop profile, with a notification service). Off by default: the device's own approval window comes back with the phase 2 desktop app. | `config set policy.approvals.desktop_notifications true` | yes |

### Root and elevation: `policy.privilege`

| Setting | Values | Default | What it does | CLI | Portal |
|---|---|---|---|---|---|
| `policy.privilege.allow_root` | `true`, `false` | `false` | Whether the client may run as root (Linux) or an elevated administrator (Windows). Off, it refuses to start as either. A dedicated user is safer (`setup --create-user`). | `config set policy.privilege.allow_root true` | yes |
| `policy.privilege.elevation` | `off`, `sudo` | `off` | `sudo`: a command that starts with `sudo ` runs as root, with the password stored on the device (below) or a sudoers rule that asks none. Linux only. Such a command always asks, in every mode, unless it is on `never_ask`; a client that already runs as root elevates nothing and runs `sudo ...` as an ordinary command, without this question; `sudo` with options of its own is refused; under Landlock it is refused (Folders mode needs `folders_shell = "unconfined"`). It needs the systemd unit's own cgroup, so that `panic` can kill root's processes; where a command's cgroup cannot be made or joined, the command does not run. | `sudo activate` / `sudo deactivate` (or `config set policy.privilege.elevation sudo`) | yes |
| `policy.privilege.sudo_path` | absolute path | `/usr/bin/sudo` | The sudo the client runs. | `config set policy.privilege.sudo_path /usr/local/bin/sudo` | no |
| `policy.privilege.secret_storage` | `memory`, `file`, `keyring` | `memory` | Where the elevation password is kept. `memory`: only in the running client, which makes itself undumpable; set it again after each start, and `panic` forgets it. `file`: a 0600 file, `~/.config/pithagoras-sync/elevation.secret`, which survives restarts (`sudo set` then also works while the client is not running). `keyring`: the Secret Service (Linux only; Windows refuses it, having no sudo), entry `application=pithagoras-sync name=elevation`; survives restarts like the file. A keyring that is missing, locked or whose prompt is cancelled is an error, never a fallback: the client starts without the password and its log and `status` say why, `unlock` says it unlocked but could not load the password, and `sudo set` fails. | `config set policy.privilege.secret_storage keyring` | no |

`exec.shell`, `sudo_path` and `secret_storage` are device-only because a portal that could change them could point the device at a program of its choosing and have the password handed to it.

### Commands: `exec`

| Setting | Values | Default | What it does | CLI | Portal |
|---|---|---|---|---|---|
| `exec.shell` | absolute path or none | none: bash (else sh) on Linux, pwsh (else Windows PowerShell) on Windows | The shell the `bash` tool runs. | `config set exec.shell /usr/bin/zsh` | no |
| `exec.env_passthrough` | list of names | empty | Variables of the client's environment that commands also get, beyond the built-in list (`PATH`, `HOME`, `LANG`, `TZ`, the XDG folders and a few more). `PORTAL_*` never passes. | `config add exec.env_passthrough CARGO_HOME` | yes |
| `exec.max_running` | above 0 | `16` | Most commands running at once. | `config set` | yes |
| `exec.max_timeout_secs` | above 0 | `14400` (4 h) | The longest a command may run, whatever the portal asks for. | `config set` | yes |
| `exec.output_cap_bytes` | above 0 | `16777216` (16 MiB) | Output beyond this per command is dropped. | `config set` | yes |

## Sudo access and the elevation password

Two things make `sudo <command>` work for the agent: the setting `policy.privilege.elevation = sudo` ("sudo access is active") and the password sudo asks for. The `sudo` command group sets both. The password is never a setting and never goes through the portal or a command line:

```sh
pithagoras-sync sudo set                # type the password (not echoed), then asks "Do you want to activate sudo access now? [y/N]"
pithagoras-sync sudo set --stdin        # one line from stdin, for a script on a headless machine; asks nothing
pithagoras-sync sudo set --stdin --activate   # ... and switches sudo access on (the headless script route)
pithagoras-sync sudo activate           # switch sudo access on
pithagoras-sync sudo activate --no-password   # without a stored password: a sudoers rule that asks none
pithagoras-sync sudo deactivate         # switch it off; the stored password stays
pithagoras-sync sudo clear              # forget the password, in the client and on disk
pithagoras-sync sudo clear --deactivate #   ... and switch sudo access off
pithagoras-sync sudo status             # active or not, password set or not (and where), what to do next
```

- Scripts (`--stdin`, `activate` without a terminal) are for headless machines: on `profile = "desktop"` every policy change checks the user's password in a terminal first, and `--stdin` leaves stdin as the password pipe, so it fails there; use `set` in a terminal.
- Questions are asked only in a terminal. `set` asks about activating unless sudo access is active already; with `--stdin` (stdin is the password, so there is nobody to ask) or without a terminal it asks nothing, leaves sudo access as it is and prints the hint, unless `--activate` is given. `activate` without a stored password offers to type one now (y/N); in a script it refuses and says what to run, unless `--no-password` is given. A client that runs as root has nothing to elevate and needs no password, so `activate` does not ask there. `clear` asks whether to switch sudo access off too while it is active; without a terminal it keeps it active (sudo then runs only what sudoers allows without a password) and says so, unless `--deactivate` is given.
- Switching sudo access on or off changes `policy.privilege.elevation` like `config set` does: the running client takes it at once and audits it with the old and new value, and the CLI refuses it from a command the client runs for the portal. `config set policy.privilege.elevation sudo` (or `off`) stays valid as the generic way and does the same; `sudo status` reads the same setting. `sudo set`, `sudo activate` and (on a desktop) the password check apply as for any policy change; `deactivate` and `clear` only take rights away and ask for no password. Each of them reads the config again right before it saves and changes only the elevation, so what the owner changed meanwhile (the mode, a folder) while a question waited stays.
- `deactivate` leaves the stored password in place. Where `portal_policy = "write"` the portal can switch `policy.privilege.elevation` on again (the setting is open to it), and the stored password is then used again; `sudo clear` forgets the password.
- On Windows the group exists but says "sudo access is Linux only" and fails: Windows has no sudo, so there is nothing to rename or replace there.
- `sudo set` refuses while a debugger traces the client. It does not try the password: a wrong one shows when the next `sudo` command fails with sudo's own message. (The window's Sudo access does try it, see "The graphical flow".)
- sudo gets it on stdin through the exec shim, which takes it from a private file descriptor (never argv or the environment) and closes stdin before the command starts, so the command cannot read it.
- It is replaced by `[redacted]` in command output, in every message to the portal, in the audit log and in the client's own log. A command that prints it re-encoded (base64, say) is not caught.
- The file tools refuse the stored file in every mode, grep and find skip it, and Landlock leaves it out. An unconfined command of the same user (Full mode, or `folders_shell = "unconfined"`) can still read it; only the output scrubbing then stands between it and the portal. That is why `memory` is the default.
- With `secret_storage = keyring` the password lives in the OS keyring instead of the file. That keeps it off the disk in plain text and out of the client's folders, but an unlocked keyring hands it to any unconfined process of the same user that asks, as the file does (see "The keyring" below), and servers usually have no keyring. That is why `memory` stays the default.

## The keyring

`token_storage = keyring` and `secret_storage = keyring` keep the token and the password in the OS keyring: on Linux the Secret Service on the session bus (the default collection, items with the attributes `application=pithagoras-sync` and `name=token` or `name=elevation`; `secret-tool lookup application pithagoras-sync name token` shows one), on Windows the Credential Manager (generic credentials `pithagoras-sync/token`, kept on this machine only).

What the keyring protects against: other users of the machine, a copied disk or backup, and a token file sent along by mistake. What it does not protect against: a command the agent runs unconfined as the same user (Full mode, an approved command in Ask mode, `folders_shell = "unconfined"`). Once the keyring is unlocked (on a desktop, at login), such a command can ask it for the secret with `secret-tool` or `cmdkey`-like calls just as it could read the file. Only the client's own memory is out of its reach, which is why the password's default stays `memory`.

A keyring the owner chose (`keyring` set explicitly) never falls back to the file or to memory; the only fallback is the Windows default for the token, described above. Tests and the test scripts set `PITHAGORAS_SYNC_NO_KEYRING=1`, which makes the client use no keyring at all.

A client started at login before the keyring service (no session bus yet, no `org.freedesktop.secrets` on it, or no answer) reads the token again after 3 seconds, then after twice as long each time up to 5 minutes, and connects once the keyring is there; `status` says when it tries next. A keyring that answered no (locked and its prompt cancelled or not answered, no entry) is not asked again until the owner acts (a reload, `pair`, `unlock`), so its prompt does not keep coming back. A reload while the client is connected reads the token again to see whether the pairing changed; if the keyring cannot be read then but the config names the same portal and device, the link stays up.

The password is read from the keyring at start, after the control socket is up, and an unlock prompt can keep that read waiting for minutes. `panic`, `sudo set` or `sudo clear` sent meanwhile win: what the read returns afterwards is dropped (the log says so), and a client paused at start does not read it at all; `unlock` reads it again. The CLI waits up to 3.5 minutes for the client's answer to `sudo set`, `sudo clear` and `unlock` (30 seconds for anything else), so it does not report a failure while the client still waits on the keyring's prompt and then stores or clears the password.

## The graphical flow

`gui` changes the pairing and the install, nothing else: it sets no mode, folder, protection or expiry, and pairing by link pairs exactly as `pair` does (Ask mode stays the default). What it adds is a way in that is not a terminal, so:

- A pairing link comes from a web page and is untrusted. It is parsed as strictly as `pair` parses it (unknown keys, a bad code or pin, a link over 4 KiB are refused), a plain-`http` portal on another machine is refused before anything is shown, and nothing happens until the owner answers Yes to a window that shows the parsed portal URL and device name, never the raw link. Every text from outside (the portal URL, a status line, an error) goes through the same escaping as the terminal (`\u{1b}` for an escape character) and is cut, and the dialog programs get it as plain text (`--no-markup`, or escaped markup).
- On Linux, `gui` refuses to start when a command the client runs started it (the same ancestry check as the CLI), before it shows anything, and checks again before each change. The dialog program (`zenity` or `kdialog`, from `PATH`) runs with an argv, never a shell, and an environment cleaned to the display, the session bus, the language and the theme. Answers are read from its output only, bounded.
- On a desktop profile `pair` asks for the user's password in a terminal through `su`, and so does pairing in the windows (Linux): the password is typed into the dialog program's hidden entry and given to the same `su` (`/usr/bin/su` or `/bin/su`, never one found through `PATH`) on a pseudo-terminal of its own. Both check the account the program runs as, named from the user database (`getpwuid`), not from `$USER`, which whoever started the program sets. `su` runs in a new session with that terminal as its controlling one, in an environment of only `PATH`, `LC_ALL=C` and `TERM=dumb`; the password is written to the terminal once `su` switched echo off for its prompt (PAM flushes what came before), never into an argument or the environment, and is not kept. A password with control characters is refused (the terminal would act on them), and a `su` that does not ask within 30 seconds (a login that wants a fingerprint first) is an error that points to `pair` in a terminal. A command that escaped the client's process tree (started through `systemd-run --user`, say) and clicks through the windows does not know the password. Install and uninstall never asked for one and do not here either; Windows asks none (as its CLI).
- The pairing question says what the agent may do right away: the mode this computer is in now (the effective one, which pairing keeps), so a computer switched to `full` earlier says that the agent acts with the owner's rights at once, and until when; `folders` says how many folders are granted.
- The portal URL shown in that question is the parsed one. A URL whose path holds anything but ASCII letters, digits, `-._~/` and `%XX` escapes is refused, by `pair` as well: spaces, quotes or other scripts in it could make it read as more of the question (`https://evil.example/ — verified: https://...`). The host was already limited to letters, digits, `.`, `-`, `_` and an IPv6 address.
- The notes of `install` and `pair` are shown: the install's (pairing links may not open the program) right after installing, the pairing's (the token kept in the file because the keyring did not take it) with how things stand after pairing.
- Sudo access (Linux, not as root) is the one policy change the windows make, and they make it like `sudo set` and the questions after it: the password, then the offer to switch sudo access on; switching it off and forgetting the password as `sudo deactivate` and `sudo clear`. The password is typed into the dialog program's hidden entry (`zenity --entry --hide-text`, `kdialog --password`) and comes back through its stdout, never its argv or environment, into a buffer sized up front and then a `Secret`. Before anything is kept it is checked with the configured `policy.privilege.sudo_path`: `sudo -k -n -v` first (if that passes, sudo asks no password here, so the window stores nothing and does not switch sudo access on: a password would prove nothing; it points to `sudo activate --no-password` in a terminal), then `sudo -k -S -p "" -v` with the password on stdin, in an environment of only `PATH` and `LC_ALL=C`, for at most 60 seconds. `-k` neither uses cached credentials nor leaves any, so the check unlocks nothing for later. A refused password is never kept. That check is also the owner's proof for switching sudo access on, where a terminal would run `su`: a command of the agent that sends input to the windows does not know the password. The window then offers to switch sudo access on only right after a password passed, and checks again that no command of the client's started it before each step. sudo logs a failed check like any failed sudo (to the auth log, perhaps a mail to root).
- The windows speak English or German (`i18n.rs`): on Linux after `LANGUAGE`, `LC_ALL`, `LC_MESSAGES` and `LANG` as gettext reads them, on Windows after the display language (`GetUserDefaultUILanguage`); English otherwise. Errors from below the windows (the connector, the keyring, sudo) stay English inside the translated sentence. GLib takes a dialog program's arguments in the locale's charset and refuses any non-ASCII text (an umlaut, the `…` of a shortened text) when the locale is not installed or not UTF-8, and then shows no window at all (a question reads as No). So when `locale -a` does not list the session's locale as a UTF-8 one, the dialog program gets `LC_ALL=C.UTF-8` (or `en_US.UTF-8`) and `LANGUAGE` set to the windows' language.
- It never starts by itself under `run` (which the units `install` and `setup` write always name), in a terminal (without a command the help shows, as before), or without a display (it says so on stderr, in `gui.log` beside the client's log and as a notification).

## Other commands that change what the portal may do

| Command | What it does |
|---|---|
| `pithagoras-sync panic` | Closes the link, kills every command, denies every call (pending approvals included) and forgets the elevation password held in memory, until `unlock`. |
| `pithagoras-sync unlock` | Ends a pause; reloads the stored password when storage is `file`. |
| `pithagoras-sync update [--check]` | Replaces the program the running client was started from (else the one you ran) with a newer signed release and restarts the client. Never changes a setting. |
| `pithagoras-sync status` | Mode, folders, approvals, elevation, the connection. |
| `pithagoras-sync gui [<link>]` | The graphical flow ([install.md](install.md)): install, pair (from a `pithagoras-sync://` link the browser hands over, or one pasted in), status, the log, uninstall with or without `--purge`. The program started with no command from a file manager or the menu, or with a pairing link alone, runs it too. It runs the code of `install`, `pair` and `uninstall` and changes no setting of its own; see "The graphical flow" below. |
| `pithagoras-sync uninstall --purge [--yes] [--print]` | Stops the client, undoes `install` and removes its pairing, config (folders and policy included), token, stored password, audit log, log and update records; the program stays. On Linux refused from the commands the client runs; on Windows commands run unconfined and can run it (see `windows.md`). |

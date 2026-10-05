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
- On Linux, a change from a command the client runs for the portal (a process descending from the client) is refused, whatever the command: `config`, `mode`, `folder`, `secret`, `approve`, `deny`, `unlock`, `update`. The agent cannot widen its own rights through the shell. Windows has no such check yet (windows.md).

## The settings

"Portal" says whether `policy.set` may change the setting when `portal_policy = "write"`: **yes**, **no** (device only: in the document the portal reads, listed under `device_only`), or **never** (not in the portal's document at all).

### Top level

| Setting | Values | Default | What it does | CLI | Portal |
|---|---|---|---|---|---|
| `profile` | `headless`, `desktop` | detected (`desktop` when a graphical session runs) | `desktop` makes every policy change ask for the user's password and allows desktop notifications for approvals. Takes effect after a restart of the client. | `config set profile desktop` | never |
| `portal_policy` | `off`, `read`, `write` | `read` | What the portal may do with these settings. `off`: it neither sees nor changes them (`hello` does not announce `policy`). `read`: the Devices tab shows them. `write`: the owner's portal session may change everything marked "yes" below, widening included (Full mode, folders, tools). | `config set portal_policy write` | never |
| `portal` | | | The pairing: portal URL, pin, device id and name. | `pair`, `unpair` | never |

### Modes: `policy.mode` and `policy.full`

| Setting | Values | Default | What it does | CLI | Portal |
|---|---|---|---|---|---|
| `policy.mode` | `ask`, `folders`, `full` | `ask` | **Ask**: every call asks for approval. **Folders**: file calls inside the granted folders only, commands only where a folder grants `execute`. **Full**: everything the user can do, with the protections below still on. | `mode ask\|folders\|full` | yes |
| `policy.full.expiry_hours` | hours, `0` = never | `8` | How long Full lasts before the device falls back to Ask. | `mode full --expiry-hours 2` | yes |
| `policy.full.until_ms` | Unix ms or none | none | When the current Full mode ends; set by the device when Full is switched on. | set by `mode full` | no effect (the device dates it) |
| `policy.full.protected_paths` | `true`, `false` | `true` | Protected paths (below) ask in Full mode too. | `config set` | yes |
| `policy.full.pattern_prompts` | `true`, `false` | `true` | Risky commands ask in Full mode: `sudo`, `su`, `doas`, `pkexec` and the like, `git push`, a download piped into a shell, `rm -r` outside the working folder. | `config set` | yes |
| `policy.full.taint_prompts` | `true`, `false` | `true` | Calls from a chat the portal marked as having seen untrusted content (`ctx.tainted`) ask in Full mode too. | `config set` | yes |

### Folders

| Setting | Values | Default | What it does | CLI | Portal |
|---|---|---|---|---|---|
| `policy.folders` | list of `{path, access, execute}` | empty | The folders Folders mode allows. `path` absolute; `access` `ro` or `rw`; `execute` lets commands run with that folder as their working folder. | `folder add <path> [--rw] [--exec]`, `folder remove <path>`, `folder list` | yes |
| `policy.folders_shell` | `landlock`, `prompt`, `unconfined` | `landlock` | How commands run in Folders mode. `landlock`: under Landlock (Linux 5.13+), writable only inside `rw` folders, unable to read protected or denied paths; without kernel support every command asks instead. `prompt`: every command asks. `unconfined`: commands run with all of the user's rights, only the risky-command patterns ask. | `config set policy.folders_shell unconfined` | yes |
| `policy.allow_globs` | list of `{glob, access}` | empty | Files the file tools may reach in Folders mode outside the folders (`~/.config/app/*.toml`). Commands are not affected. | `config add policy.allow_globs '{"glob": "~/notes/*.md", "access": "ro"}'` | yes |

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

A command rule is exactly one of `{"exact": "..."}` (the whole command, spaces normalised), `{"prefix": "..."}`, `{"glob": "..."}` (`*` matches anything) or `{"regex": "..."}` (searched in the command; anchor with `^...$`). Command rules are a filter on the text the portal sends, not a sandbox: a determined command can be written to slip past them. Only Landlock confines the shell.

### Protected paths: `policy.protected`

Built in: `~/.ssh`, `~/.gnupg`, keyrings and password managers, cloud credentials, browser and mail profiles, shell start-up files, autostart folders, the client's own folders and more. Writes into folders named in `tool_config` (anywhere in a path) ask as well. Protected paths ask in Ask and Folders mode, and in Full mode while `policy.full.protected_paths` is on.

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

The first answer wins. "Of its kind" means reads, writes or commands from the same chat, and is offered only for Ask mode's own question; protected paths, patterns, taint and elevated commands ask every time.

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
| `policy.privilege.elevation` | `off`, `sudo` | `off` | `sudo`: a command that starts with `sudo ` runs as root, with the password stored on the device (below) or a sudoers rule that asks none. Linux only. Such a command always asks, in every mode, unless it is on `never_ask`; `sudo` with options of its own is refused; under Landlock it is refused (Folders mode needs `folders_shell = "unconfined"`). It needs the systemd unit's own cgroup, so that `panic` can kill root's processes. | `config set policy.privilege.elevation sudo` | yes |
| `policy.privilege.sudo_path` | absolute path | `/usr/bin/sudo` | The sudo the client runs. | `config set policy.privilege.sudo_path /usr/local/bin/sudo` | no |
| `policy.privilege.secret_storage` | `memory`, `file` | `memory` | Where the elevation password is kept. `memory`: only in the running client, which makes itself undumpable; set it again after each start, and `panic` forgets it. `file`: a 0600 file, `~/.config/pithagoras-sync/elevation.secret`, which survives restarts. | `config set policy.privilege.secret_storage file` | no |

`exec.shell`, `sudo_path` and `secret_storage` are device-only because a portal that could change them could point the device at a program of its choosing and have the password handed to it.

### Commands: `exec`

| Setting | Values | Default | What it does | CLI | Portal |
|---|---|---|---|---|---|
| `exec.shell` | absolute path or none | none: bash (else sh) on Linux, pwsh (else Windows PowerShell) on Windows | The shell the `bash` tool runs. | `config set exec.shell /usr/bin/zsh` | no |
| `exec.env_passthrough` | list of names | empty | Variables of the client's environment that commands also get, beyond the built-in list (`PATH`, `HOME`, `LANG`, `TZ`, the XDG folders and a few more). `PORTAL_*` never passes. | `config add exec.env_passthrough CARGO_HOME` | yes |
| `exec.max_running` | above 0 | `16` | Most commands running at once. | `config set` | yes |
| `exec.max_timeout_secs` | above 0 | `14400` (4 h) | The longest a command may run, whatever the portal asks for. | `config set` | yes |
| `exec.output_cap_bytes` | above 0 | `16777216` (16 MiB) | Output beyond this per command is dropped. | `config set` | yes |

## The elevation password

The password sudo needs is never a setting and never goes through the portal or a command line:

```sh
pithagoras-sync secret set elevation           # typed in this terminal, not echoed
pithagoras-sync secret set elevation --stdin   # one line from stdin, for a script
pithagoras-sync secret status
pithagoras-sync secret clear                   # forget it, in the client and on disk
```

- `set` refuses while a debugger traces the client. It does not try the password: a wrong one shows when the next `sudo` command fails with sudo's own message.
- sudo gets it on stdin through the exec shim, which takes it from a private file descriptor (never argv or the environment) and closes stdin before the command starts, so the command cannot read it.
- It is replaced by `[redacted]` in command output, in every message to the portal, in the audit log and in the client's own log. A command that prints it re-encoded (base64, say) is not caught.
- The file tools refuse the stored file in every mode, grep and find skip it, and Landlock leaves it out. An unconfined command of the same user (Full mode, or `folders_shell = "unconfined"`) can still read it; only the output scrubbing then stands between it and the portal. That is why `memory` is the default.
- The OS keyring is not used: unlocked, it hands the password to every process of the user, as the file does, and servers have none.

## Other commands that change what the portal may do

| Command | What it does |
|---|---|
| `pithagoras-sync panic` | Closes the link, kills every command, denies every call (pending approvals included) and forgets the elevation password held in memory, until `unlock`. |
| `pithagoras-sync unlock` | Ends a pause; reloads the stored password when storage is `file`. |
| `pithagoras-sync update [--check]` | Replaces the program with a newer signed release and restarts the client. Never changes a setting. |
| `pithagoras-sync status` | Mode, folders, approvals, elevation, the connection. |

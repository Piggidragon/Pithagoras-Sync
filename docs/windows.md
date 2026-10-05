# Windows

Phase 1 on Windows gives the same remote access as on Linux: the agent's file, shell and git tools, no GUI. Linux comes first: no Windows choice may slow down or weaken the Linux design, so where Windows cannot do what Linux does, Windows gets less, not Linux.

**Status: built, not yet run on Windows.** The workspace compiles and passes clippy for `x86_64-pc-windows-msvc` (with `cargo-xwin` on Linux). The Windows path rules are pure functions tested on Linux. Everything else on this page is design and code that has not run on a Windows machine yet. `scripts/windows-vm-test.sh` runs the Windows tests on a test VM; until it has passed there, treat every Windows statement as unverified.

## Shell

- The `bash` tool runs PowerShell: `pwsh.exe` if it is on `PATH`, else Windows PowerShell (`powershell.exe`). The config can name another shell (`[exec] shell = 'C:\path\to\shell.exe'`).
- The tool keeps its name `bash`. `hello` and `device.info` say which shell it is (`pwsh` or `powershell`), so the portal can tell the model to write PowerShell.
- The command goes in as `-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand <base64 of UTF-16LE>`. The encoding avoids every quoting problem; `-NoProfile` keeps the user's profile scripts out; `Bypass` applies to that one process only.
- A shell that is not PowerShell gets `-c <command>`, as on Linux.
- The environment is scrubbed as on Linux, with a Windows list (`PATH`, `PATHEXT`, `SystemRoot`, `ComSpec`, `TEMP`, `USERPROFILE`, `APPDATA` and similar). `PORTAL_*` never passes.

## Process trees: Job Objects

- Each command runs under a small shim (`pithagoras-sync __exec-shim`). The client creates a Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, starts the shim, assigns it to the job, and only then lets it go on (the shim waits for one byte on stdin). Everything the command starts is in the job, `Start-Process` children included.
- Timeout, `exec.signal` (every signal), `panic` and a dropped connection terminate the job. If the client itself dies, the job handle closes and Windows kills the job.
- Linux's cgroups and child subreaper have no part in this; the Windows code sits behind `#[cfg(windows)]` next to them.

## Folders mode: file tools only

Windows has no Landlock. The default Folders shell setting (`landlock`) falls back to `prompt`: **every command in Folders mode asks for approval** (below). The owner can choose `folders_shell = "unconfined"` in the config: then commands run with all of the user's rights, and Folders mode confines the file tools only. Full mode runs commands as on Linux.

## Approvals: through the portal and the CLI

As on Linux, Ask is the default mode, and approvals go to the portal (`approval.requested`), which answers with `approval.answer`; the owner can also answer in a terminal with `pithagoras-sync approvals`, `approve <id>` and `deny <id>`, over the named pipe. The Windows client runs with the headless profile, so there are no desktop notifications: a toast with Allow and Deny buttons that reports the click back to a plain `.exe` needs an app identity (an AppUserModelID with a registered COM activator, or a packaged app), which was not attempted. The phase 2 desktop app will have its own approval window. **Unverified on Windows.**

## Elevation: not built

`policy.privilege.elevation = "sudo"` is Linux only. On Windows, with elevation set to `sudo`, a `sudo ...` command is denied (with it off, `sudo` is just a word of the command), and `secret set elevation` is refused; there is no UAC counterpart in phase 1. `policy.privilege.allow_root` (off by default) also covers an elevated administrator: the client refuses to start in an elevated session unless it is on.

## Updates

`pithagoras-sync update` works as on Linux (signed manifest, checks, version check of the new binary), except that a running `.exe` cannot be replaced: the old program is renamed to `pithagoras-sync.exe.old` first, the new one takes its name, and the `.old` file is removed by the next update. The logon task's restart on failure (every minute) starts the new version. **Unverified on Windows.**

## Who may change the policy

- As on a headless Linux machine, the Windows account login is the authentication: whoever runs `pithagoras-sync mode` or `folder` as that user is the owner. There is no password prompt.
- The control channel is a named pipe, `\\.\pipe\pithagoras-sync-<hash of the config folder>`, created with `first_pipe_instance` and `reject_remote_clients`. The client opens it before it connects and does not start without it, so `panic` always reaches it. A program that took the name first (the name is predictable) makes the client refuse to start; it cannot receive what the owner's CLI sends to a running client, since the client always keeps one instance of the pipe open. The default pipe security gives other users of the machine read access only; a request needs write access. **Unverified on Windows.**
- Linux refuses `unlock`, `reload` and policy edits from processes that descend from the client (the agent's own commands). Windows has no such check. It would add little there: a Windows command runs only in Full mode or with an unconfined Folders shell, and in both it has the user's full rights, so it could edit the config file directly. While paused, no command of the client runs at all.

## Files and paths

- The portal sends `/c/Users/alice/x` for `C:\Users\alice\x` (protocol.md, section 6). The device refuses untranslated drive letters, UNC and `\\?\` paths, backslashes, device names (`CON`, `NUL`, `COM1`...), alternate data streams (`:`), trailing dots and spaces, and wildcards. These rules are pure string functions (`sync_policy::paths::win`) with tests that run on Linux.
- Folder checks compare whole components and ignore case, as NTFS does by default.
- There is no `openat2`. Each open takes a handle and then checks the handle's final path (`GetFinalPathNameByHandleW`) against the policy, so a junction or symlink swapped in between fails the call.
- Protected paths on Windows: `.ssh`, `.gnupg`, credential and vault folders under `AppData`, password managers, browser and mail profiles, the Startup folder, PowerShell profiles, plus the machine-wide Startup folder, `System32\Tasks` and `System32\config`. The client's own folders (`%APPDATA%\pithagoras-sync`, `%LOCALAPPDATA%\pithagoras-sync`) are protected too.

## Files the client keeps

| What | Where |
|---|---|
| Config | `%APPDATA%\pithagoras-sync\config.toml` |
| Connector token | `%APPDATA%\pithagoras-sync\token` |
| Audit log, pause flag | `%LOCALAPPDATA%\pithagoras-sync\` |
| Program (after `install`) | `%LOCALAPPDATA%\Programs\pithagoras-sync\pithagoras-sync.exe` |

The token file relies on the profile folder's default permissions (the user, SYSTEM and Administrators). Linux refuses a token file others can read; Windows has no such check yet. The architecture's OS credential store (Credential Manager) is not used in phase 1 on either platform.

## Start at logon: a scheduled task, not a service

A service runs in session 0 without a desktop and as another account; the client should run as the user, like the Linux user unit. `pithagoras-sync install` therefore:

1. copies the program to `%LOCALAPPDATA%\Programs\pithagoras-sync\`,
2. writes the task definition to `%LOCALAPPDATA%\pithagoras-sync\logon-task.xml` (UTF-16 with a byte order mark, which `schtasks` reads reliably),
3. runs `schtasks /Create /TN "Pithagoras Sync" /XML <file> /F`,
4. starts it at once with `schtasks /Run` (if that fails, it starts at the next logon).

The task: a logon trigger for this user, `InteractiveToken` (runs only while the user is logged on, no stored password), `LeastPrivilege`, no time limit, restart every minute on failure, and no second instance. It runs `pithagoras-sync.exe run --detach`; `--detach` drops the console (`FreeConsole`). A console window may still flash briefly at logon, since the program is a console program so that the CLI prints in a terminal. **Unverified.** If it flashes, the fix is a small GUI-subsystem launcher, not a change to the CLI.

`pithagoras-sync install --print` shows the steps without doing them; `uninstall` ends and deletes the task and removes the program. Admin rights are not needed. `install --system` and `setup --create-user` are Linux only.

## Not on Windows in phase 1

- Desktop notifications for approvals (above); approvals work through the portal and the CLI.
- Elevation (`sudo`).
- A sandbox for the Folders shell.
- The ancestry check on the control channel (above).
- A password check before policy changes.
- `setup --create-user` and system-wide install.

# Windows

Phase 1 on Windows gives the same remote access as on Linux: the agent's file, shell and git tools, no GUI. Linux comes first: no Windows choice may slow down or weaken the Linux design, so where Windows cannot do what Linux does, Windows gets less, not Linux.

**Status: tested on one Windows machine.** The workspace is cross-built for `x86_64-pc-windows-msvc` with `cargo-xwin`, and its tests ran on a Windows test VM (Windows 10.0.26300, Windows PowerShell 5.1, no `pwsh`), together with the real client against the mock portal; [testing.md](testing.md#windows) lists what ran and what came out. What has not run there is marked **unverified** below.

## Shell

- The `bash` tool runs PowerShell: `pwsh.exe` if it is on `PATH`, else Windows PowerShell (`powershell.exe`). The config can name another shell (`[exec] shell = 'C:\path\to\shell.exe'`).
- The tool keeps its name `bash`. `hello` and `device.info` say which shell it is (`pwsh` or `powershell`), so the portal can tell the model to write PowerShell.
- The command goes in as `-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command <command>`, as one argument. `-NoProfile` keeps the user's profile scripts out; `Bypass` applies to that one process only. Not `-EncodedCommand`: with it, Windows PowerShell writes errors to a redirected stderr as CLIXML (`#< CLIXML <Objs ...>`) instead of text.
- The output is UTF-8. The command gets a console of its own without a window (`CREATE_NO_WINDOW`), switched to code page 65001 before the shell starts, so PowerShell and the programs it starts write UTF-8 rather than the OEM code page (850 on a German Windows), and no console window appears.
- A shell that is not PowerShell gets `-c <command>`, as on Linux.
- The environment is scrubbed as on Linux, with a Windows list (`PATH`, `PATHEXT`, `SystemRoot`, `ComSpec`, `TEMP`, `USERPROFILE`, `APPDATA` and similar). `PORTAL_*` never passes.

## Plain http to a local portal

On Linux the client sends nothing over plain http to a loopback port unless the connection's socket and the sockets listening on that port belong to its user or root (from `/proc/net/tcp`). Windows has no such check yet (it would need `GetExtendedTcpTable` and the owning process's token): any local account that listens on the portal's port while the portal is down gets the pairing code or the token. On a Windows machine shared with other accounts, use https with a pinned certificate.

## Process trees: Job Objects

- Each command runs under a small shim (`pithagoras-sync __exec-shim`). The client creates a Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, starts the shim, assigns it to the job, and only then lets it go on (the shim waits for its spec on stdin, which the client writes only after that; the spec is never in the command line). Everything the command starts itself is in the job, `Start-Process` children included.
- A process the command started in the background keeps running after the shell exits, as on Linux (decision 12 in `protocol.md`): while the job still has active processes (`QueryInformationJobObject`, `ActiveProcesses`), the client keeps its handle among the lingering scopes. Its output after the shell's exit is not forwarded.
- Timeout, `exec.signal` (every signal), `panic` and a dropped connection terminate the job, lingering ones included. If the client itself dies, the job handle closes and Windows kills the job. Each was tested with a hidden `Start-Process` child; the tests also check that such a child outlives a shell that exited, and dies at `panic` and when the connection drops.
- **What escapes the job:** a process that another service starts on the command's behalf is not the command's child and not in the job. A process started through WMI (`Win32_Process.Create`) survived `panic` (tested); a scheduled task, a service or an out-of-process COM server would do the same. Linux has the same gap for `systemd-run --user` and similar. The job ends the command; it is not a sandbox.
- Linux's cgroups and child subreaper have no part in this; the Windows code sits behind `#[cfg(windows)]` next to them.

## Folders mode: file tools only

Windows has no Landlock, and the client uses no restricted token, AppContainer or other confinement for commands: a command runs with all of the user's rights. The default Folders shell setting (`landlock`) therefore falls back to `prompt`: **every command in Folders mode asks for approval** (below; the approval gives the reason "Windows has no Landlock to confine commands, so every command in Folders mode asks"). The owner can choose `folders_shell = "unconfined"` in the config: then commands run without asking, and Folders mode confines the file tools only. Tested: an unconfined command read `~\.ssh` and wrote outside the folder (after the approval the client asks for when a command names a protected path). Full mode runs commands as on Linux.

## Approvals: through the portal and the CLI

As on Linux, Ask is the default mode, and approvals go to the portal (`approval.requested`), which answers with `approval.answer`; the owner can also answer in a terminal with `pithagoras-sync approvals`, `approve <id>` and `deny <id>`, over the named pipe. The Windows client runs with the headless profile, so there are no desktop notifications: a toast with Allow and Deny buttons that reports the click back to a plain `.exe` needs an app identity (an AppUserModelID with a registered COM activator, or a packaged app), which was not attempted. The phase 2 desktop app will have its own approval window. Approvals through the mock portal and their timeout were tested.

The check that notices a command naming a protected path knows the PowerShell spellings too: backslashes, any case, and `$HOME`, `$env:USERPROFILE`, `%USERPROFILE%` and `~` for the home folder. It asks; it is not a barrier, since a command can always build a path the check does not see.

## Elevation: Linux only

Elevation is `sudo` on Linux and nothing else: Windows has none, and none is planned (no UAC prompt, no stored administrator password, no Credential Manager). On Windows, with `policy.privilege.elevation = "sudo"`, a `sudo ...` command is denied (with it off, `sudo` is just a word of the command), and `secret set elevation` is refused. A command that needs administrator rights fails with Windows' own "access denied"; the owner runs it in an elevated PowerShell of his own.

`policy.privilege.allow_root` (off by default) also covers an elevated administrator: the client refuses to start in an elevated session unless it is on, and warns "running as an elevated administrator" when it is. An administrator's ssh session is always elevated (the High mandatory level), so a client started over ssh needs it; the logon task runs the client unelevated (Medium level, tested).

## Updates

`pithagoras-sync update` works as on Linux (signed manifest, checks, version check of the new binary), except that a running `.exe` cannot be replaced: the old program is renamed to `pithagoras-sync.exe.old` first, the new one takes its name, and the `.old` file is removed by the next update. A manifest may be a local path (`update --manifest C:\rel\manifest.json`); the binary is looked for beside it. `tests/update_windows.rs` tests a release replacing a running program. The client then exits with code 75, and the logon task starts it again within a minute (below). A whole update through the task, with a release key compiled in, was not run on Windows (**unverified**).

## Who may change the policy

- As on a headless Linux machine, the Windows account login is the authentication: whoever runs `pithagoras-sync mode` or `folder` as that user is the owner. There is no password prompt.
- The control channel is a named pipe, `\\.\pipe\pithagoras-sync-<hash of the config folder>`, created with `first_pipe_instance` and `reject_remote_clients`. The client opens it before it connects and does not start without it, so `panic` always reaches it. A program that took the name first (the name is predictable) makes the client refuse to start; it cannot receive what the owner's CLI sends to a running client, since the client always keeps one instance of the pipe open.
- **Who may connect:** the pipe's security is `D:P(A;;GA;;;SY)(A;;GA;;;<the user's SID>)S:(ML;;NRNW;;;ME)`: the user and SYSTEM, nobody else, and only from Medium integrity up. Windows' default pipe security would let Everyone and Anonymous connect for reading: a Low-integrity process of the user did, held 120,000 instances within 20 seconds, and the owner's `panic` then failed with "all pipe instances are busy". With the security above, the Low-integrity process was refused in every direction (tested). The CLI also retries a busy pipe for up to 10 seconds. Administrators are not in the list but can take ownership of anything on the machine, so they are not kept out. Another user is refused by the list; that was not tried with a second account (**unverified**).
- Linux refuses `unlock`, `reload` and policy edits from processes that descend from the client (the agent's own commands). Windows has no such check. It would add little there: a Windows command runs only in Full mode or with an unconfined Folders shell, and in both it has the user's full rights, so it could edit the config file directly. While paused, no command of the client runs at all.

## Files and paths

- The portal sends `/c/Users/alice/x` for `C:\Users\alice\x` (protocol.md, section 6). The device refuses untranslated drive letters (`C:\`, `c:/`), UNC (`//localhost/c$`) and `\\?\` paths, backslashes, device names (`CON`, `NUL`, `nul.txt`, `COM1`...), alternate data streams (`a.txt:hidden`, `::$DATA`), trailing dots and spaces, and wildcards. These rules are pure string functions (`sync_policy::paths::win`) with tests that run on Linux; each case above was also sent to the real client.
- Folder checks compare whole components and ignore case, as NTFS does by default. A path is resolved before it is judged: `sub\..\a.txt` and 8.3 short names (`ALONGF~1.TXT`) inside the folder work, and a short name that does not exist counts as outside it.
- There is no `openat2`. Each open takes a handle and then checks the handle's final path (`GetFinalPathNameByHandleW`) against the policy, so a junction or symlink swapped in between fails the call. A write truncates the file only after that check. Junctions and symlinks to outside the folder, and a symlink to a UNC path, are refused; `fs.grep` and `fs.find` do not follow them, and `fs.list` shows them as links.
- Protected paths on Windows: `.ssh`, `.gnupg`, credential and vault folders under `AppData`, password managers, credentials of cloud and developer tools (`.aws`, `.azure`, `AppData\Roaming\gcloud`, `.kube`, `.docker`, `.npmrc`, `.pypirc`, `.cargo\credentials.toml`, `.vault-token`), browser and mail profiles, the Startup folder, PowerShell profiles, plus the machine-wide Startup folder, `System32\Tasks` and `System32\config`. The client's own folders (`%APPDATA%\pithagoras-sync`, `%LOCALAPPDATA%\pithagoras-sync`) are protected too.
- Where Documents, the Startup folders and `System32` are, Windows says (its known folders, `SHGetKnownFolderPath`), so a Documents folder moved to OneDrive or redirected by policy has its PowerShell profiles protected there, and Windows on another drive than `C:` has its `Tasks` and `config` protected. `~\Documents\WindowsPowerShell` and `~\Documents\PowerShell` stay protected as well. Should Windows not answer, the machine-wide paths fall back to `%SystemRoot%` and `%ProgramData%`.

## Files the client keeps

| What | Where |
|---|---|
| Config | `%APPDATA%\pithagoras-sync\config.toml` |
| Connector token | `%APPDATA%\pithagoras-sync\token` |
| Audit log, pause flag | `%LOCALAPPDATA%\pithagoras-sync\` |
| Log of the logon task's client | `%LOCALAPPDATA%\pithagoras-sync\client.log` (and `client.log.1`) |
| Program (after `install`) | `%LOCALAPPDATA%\Programs\pithagoras-sync\pithagoras-sync.exe` |

The token file relies on the profile folder's default permissions (the user, SYSTEM and Administrators). Linux refuses a token file others can read; Windows has no such check yet. The architecture's OS credential store (Credential Manager) is not used in phase 1 on either platform.

The client the logon task starts (`run --detach`) has no console, so it writes its log to `%LOCALAPPDATA%\pithagoras-sync\client.log`, plain text, with the elevation password scrubbed as everywhere. The file is capped at 1 MiB: past that it moves to `client.log.1`, replacing the one before, and a new file starts, so the log never takes more than about 2 MiB. Why the client stopped (refusing an elevated session, a broken config) is the last line there. Started in a terminal, it logs to the terminal.

## Start at logon: a scheduled task, not a service

A service runs in session 0 without a desktop and as another account; the client should run as the user, like the Linux user unit. `pithagoras-sync install` therefore:

1. ends a client the task is running (`schtasks /End`), so the program can be replaced,
2. copies the program to `%LOCALAPPDATA%\Programs\pithagoras-sync\`; if a running copy still holds it, the old one is renamed to `.old` first, as `update` does,
3. writes the task definition to `%LOCALAPPDATA%\pithagoras-sync\logon-task.xml` (UTF-16 with a byte order mark, which `schtasks` reads reliably),
4. runs `schtasks /Create /TN "Pithagoras Sync" /XML <file> /F`,
5. starts it at once with `schtasks /Run` (if that fails, it starts at the next logon).

The task names the user by SID, not by name: in an ssh session the domain reads `WORKGROUP`, which `schtasks` cannot map to the account. It has a logon trigger for this user and a second trigger that fires every minute, `InteractiveToken` (runs only while the user is logged on, no stored password), `LeastPrivilege`, no time limit, and no second instance (`IgnoreNew`). The minute trigger is what starts the client again after it exits: Task Scheduler's own restart on failure only covers a start that failed, not a program that exited with an error code (tested: after a kill, the client stayed down). With the minute trigger, the client runs again within a minute of a kill (10 seconds on the VM); while it runs, the trigger does nothing.

The task runs `pithagoras-sync.exe run --detach`; `--detach` drops the console (`FreeConsole`). On the test VM the task's client ran in the user's session at Medium integrity. Because the program is a console program (so that the CLI prints in a terminal), every start by the task opens a console window for a moment before `--detach` drops it: at logon, and each time the minute trigger starts the client again after it stopped or after an update. On the test VM this was measured on such restarts by the task, not at a real logon: a Windows Terminal window showed for about 0.3 s, a classic console window for under 60 ms.

`pithagoras-sync install --print` shows the steps without doing them. `uninstall` ends and deletes the task and removes the task definition; the program, its `.old` copy, the config and the audit log stay. `uninstall --purge` switches the task off (`schtasks /Change /DISABLE`, so the minute trigger does not start the client again), ends it, asks a client still answering on the control pipe to exit and waits for it, deletes the task, and then removes the client's files in `%APPDATA%\pithagoras-sync` and `%LOCALAPPDATA%\pithagoras-sync` (config, token, audit log, `client.log`, update records, the task definition) and the `.old` copy next to the program. A file there that the client did not write stays, and so does its folder. The program itself stays (the running one cannot be deleted anyway); `--purge` prints its path and the `Remove-Item` to delete it. Admin rights are not needed, and it should be run from a normal shell, not an elevated one: the commands an agent runs have the same account and could turn a client folder into a junction while an elevated purge deletes in it. `install --system` and `setup --create-user` are Linux only.

## Not on Windows in phase 1

- Desktop notifications for approvals (above); approvals work through the portal and the CLI.
- Elevation: Linux only, by decision (above).
- A sandbox for commands: no restricted token or AppContainer, so the Folders shell asks for every command or runs unconfined.
- Keeping processes started through WMI, the Task Scheduler or other services within the job.
- The ancestry check on the control channel (above).
- A password check before policy changes.
- A permission check on the token file.
- `setup --create-user` and system-wide install.
- Each time the task starts the client (at logon, and when it starts it again after a stop or an update) a console window can flash for a fraction of a second; a launcher without console comes with the graphical install (issue #6).

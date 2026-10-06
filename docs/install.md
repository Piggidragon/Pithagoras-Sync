# Installing Pithagoras Sync without a terminal

This page is for people who want to connect their computer to their Pithagoras portal and never open a terminal. It says what you see, what each window does, and how to remove the program again. A server, or anyone who prefers the command line, follows [the README](../README.md) instead; nothing below changes that way.

Pithagoras Sync works on Windows 10 and 11 and on Linux desktops (GNOME, KDE and others). On Linux it shows its windows with `zenity` or `kdialog`, which most desktops have; if neither is installed, install one of them (`sudo apt install zenity`) or use the command line. Only a copy the system installed counts (one root alone can change, as in `/usr/bin`): a `zenity` in your home folder is not used, since the windows ask for your passwords. For the same reason the program keeps other programs of your user out of its memory while its windows are open, and while something traces it (a debugger) it asks for no password: it says "Pithagoras Sync is being traced" and closes.

The windows speak English or German, as your desktop does: on Linux the language settings of your session (`LANGUAGE`, `LC_ALL`, `LC_MESSAGES`, `LANG`), on Windows the display language. Any other language gets English. The quotes below are the English texts; the German windows say the same in German. The command line stays English.

## 1. Download and start it

- **Windows:** download `pithagoras-sync-x86_64-windows.exe` from the [release page](https://github.com/Piggidragon/Pithagoras-Sync/releases) and double click it. The program is not signed yet, so Windows SmartScreen may say "Windows protected your PC": click "More info", then "Run anyway". (Signing is planned, issue #7.)
- **Linux:** download `pithagoras-sync-x86_64-linux`, mark it as executable (in the file manager: Properties, Permissions, "Allow executing file as program") and double click it. Some file managers ask whether to run it or show it: choose Run.

## 2. Install

A window asks:

> Install Pithagoras Sync for *you*? It copies the program to *a folder in your home*, starts it at login, and opens pithagoras-sync:// links (the pairing link in the portal).

**Yes** installs it for your user only, without administrator rights:

- the program goes to `~/.local/bin/pithagoras-sync` (Linux) or `%LOCALAPPDATA%\Programs\pithagoras-sync\pithagoras-sync.exe` (Windows);
- it starts now and at every login, in the background (a systemd user unit on Linux, a logon task on Windows);
- your desktop learns that `pithagoras-sync://` links open it, and "Pithagoras Sync" appears in the menu (Linux) so you can open these windows again later.

**No** changes nothing and closes the window.

## 3. Pair with your portal

In the portal, open Settings, Devices, "Pair a device". There are two ways to pair:

- **Click the link** the portal shows. Your browser asks whether to open it with Pithagoras Sync; allow it.
- **Paste it.** If the program is still open after installing, it asks you to "Paste the pairing link from the portal's Devices page". Copy the link in the portal and paste it there (on Windows: copy it, then press OK; the program reads it from the clipboard). With nothing pasted, or no text in the clipboard, it says so and asks again.

Either way, a window then shows the portal it would pair with and the name your computer will have there:

> Pair this computer with the Pithagoras portal https://portal.example as "my-laptop"?

Below it says what the agent may do right after pairing: this computer's mode, which pairing keeps. Normally that is "every call asks you first"; if you switched this computer to `folders` or `full` earlier, the window says so, and for `full` that the agent then acts with your rights right away. For a portal on this computer over plain `http` it adds who else could answer on its port, as `pair` does ([windows.md](windows.md#plain-http-to-a-local-portal)).

Check that this is your portal. **Yes** pairs; **No** changes nothing. A link that is not a valid pairing link, that names a portal on another machine over plain `http`, or whose portal address has spaces or other characters a real address does not need (it could make the question read differently) is refused before anything happens.

On a Linux desktop it then asks for your password (the one you log in with), as `pithagoras-sync pair` does in a terminal: pairing decides whose agent may use this computer, and a program of the agent that clicks through the windows does not know it. It is checked with `su` and not kept. A wrong one, or a cancel, changes nothing. When `su` fails for another reason (an expired password, say), the window shows what it said instead of calling the password wrong. If it cannot be checked (some login setups ask for a fingerprint or a security key instead), pair in a terminal: `pithagoras-sync pair '<link>'`. Windows asks no password here; the Windows login is the check there ([windows.md](windows.md)).

After pairing it waits a few seconds and tells you how it stands: "Pithagoras Sync is running, connected to *your portal*, and starts at login", or "Installed, not connected yet" with the reason, and where its log is. A connection to the portal of an earlier pairing, still open while the client switches, does not count as connected; after an unpair, it shows as not paired. Notes come with it, for example that the keyring did not take the pairing's token and it is kept in a file instead. Notes of the install (for example that pairing links may not open the program, so paste them) are shown right after installing.

From now on the portal's agent can ask to use this computer. Until you change it, every file access and command asks you first; you answer in the portal's Devices tab. What else you can allow (folders, a mode without questions) is in [permissions.md](permissions.md).

## 4. Later: status, pairing again, the log

Open Pithagoras Sync again (from the menu on Linux, or by double clicking the program). Once it is installed and paired, it shows a menu:

- **Status:** whether it runs, the portal, the mode, the folders it may use, approvals waiting for you and (Linux) whether sudo access is on.
- **Pair again:** pair with another portal, or again with the same one (it asks before it replaces the pairing).
- **Sudo access** (Linux only): see below.
- **Open log:** the client's log in a text editor. On Linux, without a log file, that is the client's lines from the journal; for a client the system unit runs (`install --system`, `setup`) the system journal, which only root and the groups `systemd-journal` and `adm` can read.
- **Uninstall:** see below.
- **Quit:** closes the window; the client keeps running in the background.

## 5. Sudo access (Linux)

The portal's agent can run commands as root (`sudo <command>`) only if you allow it here and give the client your sudo password. The password stays on this computer; the agent never sees it, and every such command still asks you first.

Choose **Sudo access** in the menu. A window says whether sudo access is on and whether a password is stored, and offers:

- **Enter the password:** a field that shows dots, not what you type. The program checks the password with `sudo` itself before it keeps anything: a wrong one is refused ("sudo did not accept this password", with sudo's last line unless that line holds what you typed), and nothing changes. A right one goes to the running client (or, if you chose to keep it in a file or the keyring, there, for the client's next start). It then asks "Switch sudo access on now?"; **Yes** switches it on, **No** keeps the password and leaves sudo access off.
- **Switch sudo access off** (when it is on): the password stays.
- **Forget the password** (when one is stored): it asks first, and if sudo access is on, whether to switch it off too.
- **Back.**

If `sudo` asks you no password on this computer (a rule in sudoers says so), there is nothing to store and the window says so; switching sudo access on then is a terminal command, `pithagoras-sync sudo activate --no-password`, because the window cannot tell that you are the one asking.

By default the client keeps the password in its memory only, so after a restart (a reboot, an update) enter it again. Without the client running it cannot take it then: the window says to start the client first. [permissions.md](permissions.md) explains the other places (`policy.privilege.secret_storage`).

## 6. Uninstall

Choose **Uninstall** in the menu. Where the system unit runs the client (`install --system`, `setup`) only root can remove it: the window says so right away, with the command (`sudo pithagoras-sync uninstall --system`). Otherwise it asks twice:

1. "Uninstall Pithagoras Sync?" **No** changes nothing.
2. "Also remove the pairing and all settings?" **Yes** removes everything the client keeps: the pairing, the settings with their folders, the logs, a password or token in the keyring. **No** keeps them, so a later install picks up where you left off.

Either way the client stops, no longer starts at login, the menu entry goes and pairing links no longer open it. The program file itself stays where it is, and the window says where, so you can delete it. Notes of the steps come with it, as the command line prints them (for example that the menu may show the entry until the next login, or a folder that stays because something in it is not the client's). Remove the device in the portal as well (Settings, Devices).

If removing fails halfway, the window says what failed and that uninstalling again goes on with what is left. Where the client was stopped for it and is still installed, it is started again first, so the computer does not stay offline.

## What the windows never do

- They never pair, install or uninstall without your Yes.
- They never show or send your passwords. The sudo password is typed into a field that hides it, checked with `sudo` on this computer and kept only here; it never goes to the portal, into a log or onto a command line.
- On Linux, a command that the portal's agent runs on this computer cannot use them to pair or uninstall: they refuse before they show anything, as the command line does. On a desktop, pairing also needs your password. Windows has no such check yet ([windows.md](windows.md)).

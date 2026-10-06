# Installing Pithagoras Sync without a terminal

This page is for people who want to connect their computer to their Pithagoras portal and never open a terminal. It says what you see, what each window does, and how to remove the program again. A server, or anyone who prefers the command line, follows [the README](../README.md) instead; nothing below changes that way.

Pithagoras Sync works on Windows 10 and 11 and on Linux desktops (GNOME, KDE and others). On Linux it shows its windows with `zenity` or `kdialog`, which most desktops have; if neither is installed, install one of them (`sudo apt install zenity`) or use the command line.

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
- **Paste it.** If the program is still open after installing, it asks you to "Paste the pairing link from the portal's Devices page". Copy the link in the portal and paste it there (on Windows: copy it, then press OK; the program reads it from the clipboard).

Either way, a window then shows the portal it would pair with and the name your computer will have there:

> Pair this computer with the Pithagoras portal https://portal.example as "my-laptop"?

Check that this is your portal. **Yes** pairs; **No** changes nothing. A link that is not a valid pairing link, or that names a portal on another machine over plain `http`, is refused before anything happens.

After pairing it waits a few seconds and tells you how it stands: "Pithagoras Sync is running, connected to *your portal*, and starts at login", or "Installed, not connected yet" with the reason, and where its log is.

From now on the portal's agent can ask to use this computer. Until you change it, every file access and command asks you first; you answer in the portal's Devices tab. What else you can allow (folders, a mode without questions) is in [permissions.md](permissions.md).

## 4. Later: status, pairing again, the log

Open Pithagoras Sync again (from the menu on Linux, or by double clicking the program). Once it is installed and paired, it shows a menu:

- **Status:** whether it runs, the portal, the mode, the folders it may use.
- **Pair again:** pair with another portal, or again with the same one (it asks before it replaces the pairing).
- **Open log:** the client's log in a text editor.
- **Uninstall:** see below.
- **Quit:** closes the window; the client keeps running in the background.

## 5. Uninstall

Choose **Uninstall** in the menu. It asks twice:

1. "Uninstall Pithagoras Sync?" **No** changes nothing.
2. "Also remove the pairing and all settings?" **Yes** removes everything the client keeps: the pairing, the settings with their folders, the logs, a password or token in the keyring. **No** keeps them, so a later install picks up where you left off.

Either way the client stops, no longer starts at login, the menu entry goes and pairing links no longer open it. The program file itself stays where it is, and the window says where, so you can delete it. Remove the device in the portal as well (Settings, Devices).

## What the windows never do

- They never pair, install or uninstall without your Yes.
- They never show or send your passwords. Storing the password for `sudo` stays a terminal command (`pithagoras-sync sudo set`); the windows have no password field.
- On Linux, a command that the portal's agent runs on this computer cannot use them to pair or uninstall: they refuse before they show anything, as the command line does. Windows has no such check yet ([windows.md](windows.md)).

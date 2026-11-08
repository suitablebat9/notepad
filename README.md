# Notepad

A simple dark-mode notepad for your Proxmox Linux container. Python 3.11+ and SQLite; no npm, Docker, or third-party Python packages required.

## What it does

- Create channels and multiple plain-text notes per channel.
- Paste or edit on one device; see saved changes on another within about three seconds.
- Autosave after a short typing pause.
- Optionally password-protect a channel. Channel passwords have no minimum length; leave blank for an open channel.
- Admin sign-in can read, edit, and delete every note, including protected notes. Admins can rename/delete channels and change/remove channel passwords.
- Conflicting edits are rejected, with your unsaved draft left in the editor. Copy the draft before selecting “Reload latest.”

## Install in Proxmox

Use a Debian or Ubuntu LXC container with systemd, a network address, and Python 3.11 or newer. Run the following **inside the container**, not on the Proxmox host.

Run this in the container's root console:

```sh
apt-get update && apt-get install -y curl ca-certificates
curl -fsSL https://raw.githubusercontent.com/suitablebat9/notepad/main/install.sh -o /tmp/install-notepad.sh
sh /tmp/install-notepad.sh
```

The script downloads Notepad, installs Python, prompts for an admin password (12+ characters), and starts the service on boot. Then open `http://YOUR-CONTAINER-IP:8080` on any device. Select **Admin sign in** to manage all notes.

If you downloaded or cloned this repository instead, run `sh install.sh` from its folder.

The installer creates a dedicated service user, stores the app at `/opt/notepad`, and stores the database at `/var/lib/notepad/notes.db`. The service starts on boot. No credentials or test data are included in this package.

## Access model

Anyone who can reach the site can create channels and read/edit notes in open channels. Protected channels require their password. Only admins can delete notes or change/delete channel settings. Channel names and note counts are visible to all visitors. Channel passwords restrict access; they do not encrypt notes from the administrator. Notes are stored as plain text in SQLite; passwords use salted scrypt hashes.

Use the container address on your private network, or a private VPN for remote access. For an internet-facing deployment, place an HTTPS reverse proxy with access controls and request limits in front of the app. The bundled Python server is intended for a small personal/private installation.

## Cloudflare Tunnel / HTTPS reverse proxy

HTTP and HTTPS requests matching the public Host header work automatically, including TLS terminated by Cloudflare Tunnel. Forward the tunnel to container port 8080. If you configured a Host header override, or want to pin the public address, create `/etc/notepad.env` with your exact external origin (no trailing slash):

```ini
PUBLIC_ORIGIN=https://notes.example.com
COOKIE_SECURE=1
```

Then restart with `systemctl restart notepad`. Restrict direct access to port 8080 to your proxy when using this setup. Do not set `COOKIE_SECURE=1` for plain HTTP LAN access; browsers will not send the session cookie over HTTP.

## Maintenance

```sh
systemctl status notepad
journalctl -u notepad -n 50
systemctl restart notepad
```

Reset the admin password:

```sh
runuser -u notepad -- env DATA_DIR=/var/lib/notepad python3 /opt/notepad/server.py --set-admin
systemctl restart notepad
```

Back up the database while the service is stopped:

```sh
systemctl stop notepad
cp -a /var/lib/notepad /root/notepad-backup
systemctl start notepad
```

To restore, stop the service, restore the contents of that backup into `/var/lib/notepad`, run `chown -R notepad:notepad /var/lib/notepad`, then start the service. Backups contain all notes and password hashes, so keep them private. Use a fresh backup destination for each backup.

To update the installed app, download and run the current installer. Your notes and admin password are preserved:

```sh
curl -fsSL https://raw.githubusercontent.com/suitablebat9/notepad/main/install.sh -o /tmp/install-notepad.sh
sh /tmp/install-notepad.sh
```

Refresh the website after updating. If you still get “Origin not allowed,” set `PUBLIC_ORIGIN` in `/etc/notepad.env` to the actual address you open in your browser and restart `notepad`. Replace any old example value rather than adding a duplicate.

## Run without installing a service

```sh
python3 server.py --set-admin
python3 server.py
```

Open port 8080. Data goes in the app's `data/` folder. Optional environment variables: `HOST`, `PORT`, `DATA_DIR`, `PUBLIC_ORIGIN`, `COOKIE_SECURE`.

## Checks and limitations

Run `python3 test_server.py` for tests of cross-device reads and edits, password checks, admin access, password-change revocation, deletion, persistence, CSRF, and conflict handling.

Sessions last 12 hours and reset on service restart. Login/unlock attempts are limited per connecting IP (behind a proxy this may be shared). This is polling synchronization, not live character-by-character collaboration. Unsaved drafts remain in the current editor but do not survive closing the browser. The interface warns before leaving with unsaved edits. Deletions are permanent; use backups.

The server's functional tests were run during creation. The simplified dark interface has not been browser-tested. Installation on your Proxmox container has not been performed.

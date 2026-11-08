#!/bin/sh
# Run as root INSIDE a Debian/Ubuntu LXC container.
set -eu
[ "$(id -u)" -eq 0 ] || { echo 'Run as root inside your Debian/Ubuntu container.'; exit 1; }
command -v apt-get >/dev/null || { echo 'This installer supports Debian and Ubuntu.'; exit 1; }
command -v systemctl >/dev/null || { echo 'This installer needs a container running systemd.'; exit 1; }
[ -d /run/systemd/system ] || { echo 'Start systemd inside the container first.'; exit 1; }
printf 'Installing Notepad dependencies...\n'
apt-get update
apt-get install -y python3 curl ca-certificates tar
python3 -c 'import sys; assert sys.version_info >= (3,11), "Python 3.11 or newer is required"'
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
notepad_tmp=''
cleanup() { if [ -n "$notepad_tmp" ]; then rm -rf -- "$notepad_tmp"; fi; }
trap cleanup EXIT HUP INT TERM
if [ ! -f "$source_dir/server.py" ] || [ ! -f "$source_dir/notepad.service" ] || [ ! -f "$source_dir/public/app.js" ]; then
  notepad_tmp=$(mktemp -d)
  curl -fsSL --retry 3 https://github.com/suitablebat9/notepad/archive/refs/heads/main.tar.gz -o "$notepad_tmp/source.tar.gz"
  tar -xzf "$notepad_tmp/source.tar.gz" -C "$notepad_tmp"
  source_dir="$notepad_tmp/notepad-main"
fi
python3 -m py_compile "$source_dir/server.py"
id notepad >/dev/null 2>&1 || useradd --system --home-dir /var/lib/notepad --shell /usr/sbin/nologin notepad
install -d -m 755 /opt/notepad /opt/notepad/public
install -d -o notepad -g notepad -m 700 /var/lib/notepad
install -m 644 "$source_dir/server.py" /opt/notepad/server.py
install -m 644 "$source_dir/public/index.html" "$source_dir/public/app.js" "$source_dir/public/style.css" /opt/notepad/public/
if ! runuser -u notepad -- python3 - <<'PY'
import sqlite3
from pathlib import Path
p=Path('/var/lib/notepad/notes.db')
if not p.exists(): raise SystemExit(1)
try:
 with sqlite3.connect(p) as c:
  raise SystemExit(0 if c.execute("SELECT 1 FROM settings WHERE key='admin'").fetchone() else 1)
except sqlite3.Error: raise SystemExit(1)
PY
then
  runuser -u notepad -- env DATA_DIR=/var/lib/notepad python3 /opt/notepad/server.py --set-admin </dev/tty
fi
install -m 644 "$source_dir/notepad.service" /etc/systemd/system/notepad.service
systemctl daemon-reload
systemctl enable notepad
systemctl restart notepad
systemctl is-active --quiet notepad
printf '\nNotepad installed. Open http://YOUR-CONTAINER-IP:8080\n'
printf 'Container addresses: '
hostname -I

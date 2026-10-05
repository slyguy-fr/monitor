#!/usr/bin/env bash
# Installe (ou met à jour) l'agent et l'API dans /opt/linux-task-monitor.
set -euo pipefail

PREFIX=/opt/linux-task-monitor
STATE_DIR=/var/lib/linux-task-monitor
CONF_DIR=/etc/linux-task-monitor
SRC="$(cd "$(dirname "$0")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then
    echo "Ce script doit être lancé en root." >&2
    exit 1
fi

id ltm >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin ltm

install -d "$PREFIX"
rm -rf "$PREFIX/agent" "$PREFIX/api"
cp -r "$SRC/agent" "$SRC/api" "$SRC/requirements.txt" "$PREFIX/"
find "$PREFIX/agent" "$PREFIX/api" -name __pycache__ -prune -exec rm -rf {} +
[ -x "$PREFIX/.venv/bin/python" ] || python3 -m venv "$PREFIX/.venv"
"$PREFIX/.venv/bin/pip" install -q -r "$PREFIX/requirements.txt"

install -d -m 2770 -o root -g ltm "$STATE_DIR"
install -d -m 0750 -o root -g ltm "$CONF_DIR"
if [ ! -f "$CONF_DIR/monitor.env" ]; then
    install -m 0640 -o root -g ltm "$SRC/systemd/monitor.env.example" "$CONF_DIR/monitor.env"
fi
# SQLite gives the -wal/-shm files the database's mode: make it group-writable for the API.
[ -e "$STATE_DIR/monitor.db" ] || install -m 0660 -o root -g ltm /dev/null "$STATE_DIR/monitor.db"
for db in "$STATE_DIR"/monitor.db*; do
    [ -e "$db" ] && chgrp ltm "$db" && chmod 0660 "$db"
done

install -m 0644 "$SRC/systemd/linux-task-monitor.service" \
    "$SRC/systemd/linux-task-monitor-api.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable linux-task-monitor.service linux-task-monitor-api.service
systemctl restart linux-task-monitor.service linux-task-monitor-api.service

echo "Installé. API : curl http://127.0.0.1:8000/recommendations"

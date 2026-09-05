#!/bin/sh
# Install the honeypot binary and systemd unit on a Raspberry Pi (or any
# Debian-ish host). Run as root from the repo root after copying the binary:
#
#   sudo ./deploy/install.sh /path/to/honeypot
set -eu

BIN_SRC=${1:-./target/aarch64-unknown-linux-musl/release/honeypot}
if [ ! -x "$BIN_SRC" ]; then
    echo "usage: $0 /path/to/honeypot-binary" >&2
    echo "missing executable: $BIN_SRC" >&2
    exit 1
fi

id honeypot >/dev/null 2>&1 || useradd --system --home /nonexistent --shell /usr/sbin/nologin honeypot
install -d -o honeypot -g honeypot -m 0750 /var/log/honeypot
install -d -o honeypot -g honeypot -m 0750 /var/lib/honeypot
if [ ! -f /etc/honeypot.env ]; then
    printf '%s\n' '# HONEYPOT_ARGS="--webhook https://ntfy.sh/your-topic --allow-ip 192.168.1.10"' > /etc/honeypot.env
    chmod 0640 /etc/honeypot.env
fi
install -m 0755 "$BIN_SRC" /usr/local/bin/honeypot
install -m 0644 deploy/honeypot.service /etc/systemd/system/honeypot.service
install -m 0644 deploy/logrotate /etc/logrotate.d/honeypot

# Optional: also stamp the capability on the binary for non-systemd runs.
if command -v setcap >/dev/null 2>&1; then
    setcap cap_net_bind_service=+ep /usr/local/bin/honeypot || true
fi

systemctl daemon-reload
systemctl enable honeypot.service
systemctl restart honeypot.service
systemctl --no-pager --full status honeypot.service || true

echo
echo "Honeypot installed. Logs: /var/log/honeypot/events.jsonl"
echo "Move real SSH off :22 before exposing this host. See README.md."

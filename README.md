# honeypot

Class D (internal homelab). A low-interaction multi-port TCP honeypot in Rust, aimed at a Raspberry Pi Zero 2W. It binds common attack ports, speaks just enough of each protocol to look real, logs structured JSONL, and **never executes attacker input or makes outbound connections on the attacker’s behalf**.

This is a decoy, not a shell. It is not Cowrie, not a VM, and not an LLM honeypot.

## What it pretends to be

| Service | Default port | Behavior |
|---|---|---|
| SSH | 22 | OpenSSH 8.9 banner + client version string. Password auth is **not** parsed (SSH is binary after the banner; that needs `russh` later). |
| Telnet | 23 | BusyBox login, then a fake `#` prompt. Commands are logged and answered from a canned table. `wget`/`curl` always “fail.” |
| FTP | 21 | vsFTPd USER/PASS. `PORT`/`PASV`/`EPRT`/`EPSV` are refused so this cannot be a bounce proxy. |
| HTTP | 80, 8080 | Cheap IP-camera login page. Logs method, path, User-Agent, Basic auth, and POST form credentials. |
| RTSP | 554 | 401 + Basic challenge (camera stream endpoint). |
| Redis | 6379 | `PING` → `PONG`. `AUTH` logged. `CONFIG`/`SLAVEOF`/`MIGRATE`/`MODULE`/`EVAL`/… are logged and `-ERR`. |
| RDP | 3389 | Reads the `Cookie: mstshash=` username and FINs. |

Hard rules, all of them load-bearing:

- No `std::process`. No shells. No file writes except the JSONL log.
- No outbound TCP from protocol handlers. FTP data channels are refused. Redis migration commands are ignored. HTTP does not follow URLs.
- Reads are bounded and timed out. Concurrent connections are capped (default 64).
- Excess connections are closed with FIN, not RST.
- Tokio worker threads default to 4 (Zero 2W core count).

## JSONL

One object per event, appended to `--log` (default `events.jsonl`):

```json
{"ts":"2026-09-05T04:12:01Z","svc":"ftp","dst_port":21,"src":"203.0.113.9:48122","event":"password","user":"root","pass":"admin123"}
```

`event` is one of `connect`, `connect_dropped`, `probe`, `password`, `command`, `disconnect`.

```sh
jq -r 'select(.event=="password") | [.svc,.src,.user,.pass] | @tsv' events.jsonl
scripts/daily-summary.sh /var/log/honeypot/events.jsonl
```

## Build (this machine)

```sh
cargo test
cargo build --release
# high ports, no root:
./target/release/honeypot --bind 127.0.0.1 \
  --ssh-port 2222 --telnet-port 2323 --ftp-port 2121 \
  --http-port 8080 --http-alt-port 0 \
  --rtsp-port 8554 --redis-port 16379 --rdp-port 13389 \
  --log ./events.jsonl
```

## Cross-compile for the Zero 2W

Do not compile on the Pi. Target is **aarch64** (the original Pi Zero was ARMv6; the Zero 2W is not).

```sh
cargo install cross --git https://github.com/cross-rs/cross
rustup target add aarch64-unknown-linux-gnu
# static musl binary (no glibc version fights):
cross build --release --target aarch64-unknown-linux-musl
# or glibc:
cross build --release --target aarch64-unknown-linux-gnu
scp target/aarch64-unknown-linux-musl/release/honeypot pi@zero:/tmp/honeypot
```

`make pi-musl` wraps the musl build. Release profile is size-oriented (`lto`, `opt-level = "z"`, `strip`, `panic = "abort"`). `.cargo/config.toml` sets `target-cpu=cortex-a53` for those two targets only.

## Deploy it like an appliance

1. Flash **64-bit Raspberry Pi OS Lite** or DietPi. No desktop image.
2. Enable SSH, change the default user, **move real admin SSH off :22** (e.g. `:2222`, keys only, Tailscale or a source allow-list).
3. Copy the binary and install:

```sh
scp target/aarch64-unknown-linux-musl/release/honeypot pi@zero:/tmp/honeypot
ssh pi@zero
sudo git clone … /opt/honeypot   # or copy deploy/ + the binary
sudo /opt/honeypot/deploy/install.sh /tmp/honeypot
```

`deploy/install.sh` creates a `honeypot` system user, `/var/log/honeypot`, the systemd unit, and logrotate. The unit uses `AmbientCapabilities=CAP_NET_BIND_SERVICE` so the process is not root and the capability survives binary replacement.

4. Enable **zram** instead of a swap file on the SD card.
5. Default firewall: **deny outbound** except NTP and wherever you ship logs.
6. Prefer a **separate VLAN** or a travel router in front of the Pi. Do not port-forward the whole board; forward only decoy ports.
7. Assume the process and the SD card are hostile after a while. Re-image is the recovery plan.

Confirm from another host on that isolated VLAN:

```sh
nmap -sV -p 21,22,23,80,554,3389,6379,8080 <pi>
# then hydra / curl / redis-cli against the decoy ports, never against real SSH
```

## Isolation (this is the important part)

A honeypot on the home LAN without isolation is how scanners find the NAS next.

- Do not put this on a work network without permission.
- Do not relay traffic or “hack back” source IPs.
- Do not store and execute malware samples on the Pi.
- Internet exposure on a residential IP will generate SSH credential stuffing within hours.

## Next (not in v0.1)

- Real SSH password capture via `russh` (still reject every auth, still never open a channel).
- Optional GeoIP (`maxminddb`) and a tiny local status page on a high port (`axum`).
- TLS on :443 with a generated cert.

## Deviations

- DS §1—footer credit / branding kit—not a user-facing site; this is a headless appliance binary—2026-09-05—permanent
- DS §3—responsive layout—N/A, no UI—2026-09-05—permanent
- DS §6—email—N/A—2026-09-05—permanent
- DS §9—required pages—N/A, no site—2026-09-05—permanent
- DS §11—SEO plumbing—N/A—2026-09-05—permanent
- DS §12—security headers—N/A, not an HTTP product—2026-09-05—permanent
- DS §15—Node pin / Pages CI—Rust binary; CI is cargo fmt/clippy/test—2026-09-05—permanent

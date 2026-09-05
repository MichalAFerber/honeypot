# honeypot

Low-interaction TCP honeypot for a Raspberry Pi Zero 2W. Class D homelab.

## Commands

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt
cargo build --release
# Pi Zero 2W (needs Docker + cross):
make pi-musl
```

Local demo without privileged ports:

```sh
cargo run -- --bind 127.0.0.1 --ssh-port 2222 --telnet-port 2323 \
  --ftp-port 2121 --http-port 8080 --http-alt-port 0 \
  --rtsp-port 8554 --redis-port 16379 --rdp-port 13389 --log ./events.jsonl
```

## Architecture

- `src/main.rs` — clap, tracing, 4-worker Tokio runtime.
- `src/lib.rs` — `run()`: spawn one listener task per service, wait for Ctrl-C.
- `src/net.rs` — `socket2` bind (reuseaddr, nodelay, keepalive), semaphore accept loop, bounded reads, FIN-not-RST close.
- `src/log.rs` — mpsc JSONL writer. Handlers `try_send`; a slow disk must not stall the trap.
- `src/services/` — dumb protocol handlers. Each reads a few KB, replies from a constant, logs, drops.

Safety invariants (do not “improve” these away):

- Never `std::process`, never `Command`.
- Never connect outbound from a handler (FTP `PORT`/`PASV` must 425).
- Never follow URLs the attacker sends.
- Never accept an SSH channel / Redis `MODULE` / Redis `SLAVEOF`.
- Cap concurrent connections; timeout every read.

SSH in v0.1 is banner-only. Credentials need `russh` and a host key; keep that behind a later change, and still reject every auth.

## Deploy

`deploy/honeypot.service` + `deploy/install.sh` + `deploy/logrotate`. Real admin SSH on the Pi must not share :22 with the decoy.

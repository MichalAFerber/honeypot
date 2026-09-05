use crate::event::{Event, Kind};
use crate::net::{graceful_close, read_line, write_all_timeout, App};
use crate::util::{jitter_ms, preview, truncate, MAX_FIELD};
use std::net::SocketAddr;
use tokio::net::TcpStream;

/// OpenSSH 8.9 on Ubuntu 22.04. Banner-only: raw TCP cannot parse SSH binary
/// framing, so this captures the client version string, not passwords.
/// Password auth needs russh (see README).
const BANNER: &[u8] = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n";

pub async fn handle(mut sock: TcpStream, peer: SocketAddr, app: App, port: u16) {
    app.log.emit(Event::new("ssh", port, peer, Kind::Connect));
    jitter_ms(app.jitter_ms.0, app.jitter_ms.1).await;
    let _ = write_all_timeout(&mut sock, BANNER, app.read_timeout).await;

    match read_line(&mut sock, 256, app.read_timeout).await {
        Ok(buf) if !buf.is_empty() => {
            let ident = String::from_utf8_lossy(&buf);
            let ident = ident.trim();
            let mut ev = Event::new("ssh", port, peer, Kind::Probe)
                .bytes(buf.len())
                .data(preview(&buf));
            if ident.starts_with("SSH-") {
                ev = ev.client(truncate(ident, MAX_FIELD));
            }
            app.log.emit(ev);
        }
        _ => {
            app.log
                .emit(Event::new("ssh", port, peer, Kind::Probe).data("connect-no-data"));
        }
    }

    app.log
        .emit(Event::new("ssh", port, peer, Kind::Disconnect));
    graceful_close(sock).await;
}

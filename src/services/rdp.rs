use crate::event::{Event, Kind};
use crate::net::{graceful_close, read_bounded, App};
use crate::util::{jitter_ms, preview, truncate, MAX_FIELD};
use std::net::SocketAddr;
use tokio::net::TcpStream;

/// Capture the RDP cookie (`Cookie: mstshash=username`) and close with FIN.
/// No X.224 handshake, no NLA, no outbound anything.
pub async fn handle(mut sock: TcpStream, peer: SocketAddr, app: App, port: u16) {
    app.emit(Event::new("rdp", port, peer, Kind::Connect));
    jitter_ms(app.jitter_ms.0, app.jitter_ms.1).await;

    match read_bounded(&mut sock, app.max_read.min(2048), app.read_timeout).await {
        Ok(buf) if !buf.is_empty() => {
            let user = extract_mstshash(&buf);
            let mut ev = Event::new("rdp", port, peer, Kind::Probe)
                .bytes(buf.len())
                .data(preview(&buf));
            if let Some(ref user) = user {
                ev = ev.user(user.clone());
            }
            app.emit(ev);
            if let Some(user) = user {
                app.emit(Event::new("rdp", port, peer, Kind::Password).user(user));
            }
        }
        _ => {
            app.emit(Event::new("rdp", port, peer, Kind::Probe).data("connect-no-data"));
        }
    }

    app.emit(Event::new("rdp", port, peer, Kind::Disconnect));
    graceful_close(sock).await;
}

pub fn extract_mstshash(buf: &[u8]) -> Option<String> {
    let s = String::from_utf8_lossy(buf);
    let lower = s.to_ascii_lowercase();
    let idx = lower.find("mstshash=")?;
    let rest = &s[idx + 9..];
    let end = rest.find(['\r', '\n', '\0']).unwrap_or(rest.len());
    let user = rest[..end].trim();
    if user.is_empty() {
        None
    } else {
        Some(truncate(user, MAX_FIELD))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie() {
        let pkt = b"Cookie: mstshash=Administrator\r\n";
        assert_eq!(extract_mstshash(pkt).as_deref(), Some("Administrator"));
    }
}

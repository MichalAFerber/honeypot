use crate::event::{Event, Kind};
use crate::net::{graceful_close, read_until, write_all_timeout, App};
use crate::util::{decode_basic_auth, header_value, jitter_ms, preview, truncate, MAX_FIELD};
use std::net::SocketAddr;
use tokio::net::TcpStream;

pub async fn handle(mut sock: TcpStream, peer: SocketAddr, app: App, port: u16) {
    app.log.emit(Event::new("rtsp", port, peer, Kind::Connect));
    jitter_ms(app.jitter_ms.0, app.jitter_ms.1).await;

    let raw = match read_until(&mut sock, b"\r\n\r\n", app.max_read, app.read_timeout).await {
        Ok(buf) if !buf.is_empty() => buf,
        _ => {
            app.log
                .emit(Event::new("rtsp", port, peer, Kind::Probe).data("connect-no-data"));
            app.log
                .emit(Event::new("rtsp", port, peer, Kind::Disconnect));
            graceful_close(sock).await;
            return;
        }
    };

    let text = String::from_utf8_lossy(&raw);
    let first = text.lines().next().unwrap_or("").trim_end_matches('\r');
    let cseq = header_value(&text, "cseq").unwrap_or("1");
    let auth = header_value(&text, "authorization");

    app.log.emit(
        Event::new("rtsp", port, peer, Kind::Probe)
            .bytes(raw.len())
            .data(preview(first.as_bytes()))
            .path(truncate(first, MAX_FIELD)),
    );

    if let Some(auth) = auth {
        if let Some((u, p)) = decode_basic_auth(auth) {
            app.log.emit(
                Event::new("rtsp", port, peer, Kind::Password)
                    .user(u)
                    .pass(p),
            );
        } else {
            app.log.emit(
                Event::new("rtsp", port, peer, Kind::Password).data(truncate(auth, MAX_FIELD)),
            );
        }
    }

    let resp = format!(
        "RTSP/1.0 401 Unauthorized\r\nCSeq: {cseq}\r\nWWW-Authenticate: Basic realm=\"IPCamera\"\r\nServer: HiIPCamera/V100R003\r\n\r\n"
    );
    let _ = write_all_timeout(&mut sock, resp.as_bytes(), app.read_timeout).await;

    app.log
        .emit(Event::new("rtsp", port, peer, Kind::Disconnect));
    graceful_close(sock).await;
}

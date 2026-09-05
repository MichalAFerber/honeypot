use crate::event::{Event, Kind};
use crate::net::{graceful_close, read_line, write_all_timeout, App};
use crate::util::{jitter_ms, truncate, MAX_FIELD};
use std::net::SocketAddr;
use tokio::net::TcpStream;

/// vsFTPd-style login trap. Never opens a data connection: PORT/PASV/EPRT/EPSV
/// are logged and refused so this cannot be used as a bounce proxy.
pub async fn handle(mut sock: TcpStream, peer: SocketAddr, app: App, port: u16) {
    app.emit(Event::new("ftp", port, peer, Kind::Connect));
    jitter_ms(app.jitter_ms.0, app.jitter_ms.1).await;
    let _ = write_all_timeout(&mut sock, b"220 (vsFTPd 3.0.3)\r\n", app.read_timeout).await;

    let mut username = String::new();
    let mut lines = 0usize;

    loop {
        if lines >= app.max_lines {
            break;
        }
        let buf = match read_line(&mut sock, 512, app.idle_timeout).await {
            Ok(b) if !b.is_empty() => b,
            _ => break,
        };
        lines += 1;
        let line = String::from_utf8_lossy(&buf);
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            continue;
        }
        let upper = line.to_ascii_uppercase();

        if upper.starts_with("USER ") {
            username = truncate(line[5..].trim(), MAX_FIELD);
            let _ = write_all_timeout(
                &mut sock,
                b"331 Please specify the password.\r\n",
                app.read_timeout,
            )
            .await;
        } else if upper.starts_with("PASS ") {
            let password = truncate(line[5..].trim(), MAX_FIELD);
            app.emit(
                Event::new("ftp", port, peer, Kind::Password)
                    .user(username.clone())
                    .pass(password),
            );
            let _ =
                write_all_timeout(&mut sock, b"530 Login incorrect.\r\n", app.read_timeout).await;
            break;
        } else if upper.starts_with("QUIT") {
            let _ = write_all_timeout(&mut sock, b"221 Goodbye.\r\n", app.read_timeout).await;
            break;
        } else if upper.starts_with("PORT")
            || upper.starts_with("PASV")
            || upper.starts_with("EPRT")
            || upper.starts_with("EPSV")
        {
            // Do not connect outbound. A PORT bounce would make this a proxy.
            app.emit(
                Event::new("ftp", port, peer, Kind::Command)
                    .data(truncate(line, MAX_FIELD))
                    .client("data-channel-refused"),
            );
            let _ = write_all_timeout(
                &mut sock,
                b"425 Can't open data connection.\r\n",
                app.read_timeout,
            )
            .await;
        } else {
            app.emit(Event::new("ftp", port, peer, Kind::Command).data(truncate(line, MAX_FIELD)));
            let _ = write_all_timeout(
                &mut sock,
                b"530 Please login with USER and PASS.\r\n",
                app.read_timeout,
            )
            .await;
        }
    }

    app.emit(Event::new("ftp", port, peer, Kind::Disconnect));
    graceful_close(sock).await;
}

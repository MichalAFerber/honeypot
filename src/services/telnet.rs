use crate::event::{Event, Kind};
use crate::net::{graceful_close, read_line, write_all_timeout, App};
use crate::shell::{self, Persona};
use crate::util::{jitter_ms, strip_telnet_iac, truncate, MAX_FIELD};
use std::net::SocketAddr;
use tokio::net::TcpStream;

pub async fn handle(mut sock: TcpStream, peer: SocketAddr, app: App, port: u16) {
    app.emit(Event::new("telnet", port, peer, Kind::Connect));
    jitter_ms(app.jitter_ms.0, app.jitter_ms.1).await;

    // Refuse every option; do not enable echo/linemode features.
    let _ = write_all_timeout(
        &mut sock,
        b"\xff\xfd\x03\xff\xfb\x01", // DO suppress-go-ahead, WILL echo
        app.read_timeout,
    )
    .await;
    let _ = write_all_timeout(&mut sock, shell::motd(Persona::BusyBox), app.read_timeout).await;
    let _ = write_all_timeout(&mut sock, b"login: ", app.read_timeout).await;

    let mut stage: u8 = 0; // 0 user, 1 pass, 2 fake shell
    let mut username = String::new();
    let mut commands = 0usize;

    loop {
        if commands >= app.max_lines {
            break;
        }
        let buf = match read_line(&mut sock, 512, app.idle_timeout).await {
            Ok(b) if !b.is_empty() => b,
            _ => break,
        };
        let cleaned = strip_telnet_iac(&buf);
        let line = String::from_utf8_lossy(&cleaned);
        let input = line.trim_end_matches(['\r', '\n']).trim();

        match stage {
            0 => {
                if input.is_empty() {
                    let _ = write_all_timeout(&mut sock, b"login: ", app.read_timeout).await;
                    continue;
                }
                username = truncate(input, MAX_FIELD);
                let _ = write_all_timeout(&mut sock, b"Password: ", app.read_timeout).await;
                stage = 1;
            }
            1 => {
                app.emit(
                    Event::new("telnet", port, peer, Kind::Password)
                        .user(username.clone())
                        .pass(truncate(input, MAX_FIELD)),
                );
                let _ = write_all_timeout(&mut sock, b"\r\n# ", app.read_timeout).await;
                stage = 2;
            }
            _ => {
                if input.eq_ignore_ascii_case("exit")
                    || input.eq_ignore_ascii_case("logout")
                    || input.eq_ignore_ascii_case("quit")
                {
                    break;
                }
                if !input.is_empty() {
                    commands += 1;
                    app.emit(
                        Event::new("telnet", port, peer, Kind::Command)
                            .user(username.clone())
                            .data(truncate(input, MAX_FIELD)),
                    );
                    let reply = shell::reply(Persona::BusyBox, input);
                    let _ = write_all_timeout(&mut sock, reply.as_bytes(), app.read_timeout).await;
                }
                let _ =
                    write_all_timeout(&mut sock, shell::prompt(Persona::BusyBox), app.read_timeout)
                        .await;
            }
        }
    }

    app.emit(Event::new("telnet", port, peer, Kind::Disconnect));
    graceful_close(sock).await;
}

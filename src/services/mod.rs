mod ftp;
mod http;
mod rdp;
mod redis;
mod rtsp;
mod ssh;
mod telnet;

use crate::net::{accept_loop, bind, App};
use std::net::{IpAddr, SocketAddr};
use tokio::net::TcpStream;

#[derive(Clone)]
pub enum Service {
    Ssh { port: u16 },
    Telnet { port: u16 },
    Ftp { port: u16 },
    Http { port: u16 },
    Rtsp { port: u16 },
    Redis { port: u16 },
    Rdp { port: u16 },
}

impl Service {
    pub fn name(&self) -> &'static str {
        match self {
            Service::Ssh { .. } => "ssh",
            Service::Telnet { .. } => "telnet",
            Service::Ftp { .. } => "ftp",
            Service::Http { .. } => "http",
            Service::Rtsp { .. } => "rtsp",
            Service::Redis { .. } => "redis",
            Service::Rdp { .. } => "rdp",
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            Service::Ssh { port }
            | Service::Telnet { port }
            | Service::Ftp { port }
            | Service::Http { port }
            | Service::Rtsp { port }
            | Service::Redis { port }
            | Service::Rdp { port } => *port,
        }
    }

    pub async fn handle(&self, sock: TcpStream, peer: SocketAddr, app: App, dst_port: u16) {
        match self {
            Service::Ssh { .. } => ssh::handle(sock, peer, app, dst_port).await,
            Service::Telnet { .. } => telnet::handle(sock, peer, app, dst_port).await,
            Service::Ftp { .. } => ftp::handle(sock, peer, app, dst_port).await,
            Service::Http { .. } => http::handle(sock, peer, app, dst_port).await,
            Service::Rtsp { .. } => rtsp::handle(sock, peer, app, dst_port).await,
            Service::Redis { .. } => redis::handle(sock, peer, app, dst_port).await,
            Service::Rdp { .. } => rdp::handle(sock, peer, app, dst_port).await,
        }
    }
}

pub async fn spawn_service(bind_ip: IpAddr, svc: Service, app: App) -> anyhow::Result<()> {
    let addr = SocketAddr::new(bind_ip, svc.port());
    let listener = bind(addr).map_err(|e| anyhow::anyhow!("bind {addr} ({}): {e}", svc.name()))?;
    accept_loop(listener, app, svc).await;
    Ok(())
}

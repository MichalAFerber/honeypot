use crate::event::{Event, Kind};
use serde::Serialize;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum Severity {
    Info,
    Important,
    Critical,
}

impl Kind {
    pub fn severity(self) -> Severity {
        match self {
            Kind::Connect
            | Kind::ConnectDropped
            | Kind::Probe
            | Kind::Disconnect
            | Kind::Heartbeat => Severity::Info,
            Kind::Scan => Severity::Important,
            Kind::Password | Kind::Command => Severity::Critical,
        }
    }
}

#[derive(Clone)]
pub struct Alerter {
    tx: mpsc::Sender<Event>,
}

#[derive(Clone, Debug)]
pub struct AlertConfig {
    pub webhook: Option<String>,
    pub syslog: Option<SocketAddr>,
    pub cooldown: Duration,
    pub name: String,
}

impl AlertConfig {
    pub fn disabled() -> Self {
        Self {
            webhook: None,
            syslog: None,
            cooldown: Duration::from_secs(600),
            name: "honeypot".into(),
        }
    }
}

impl Alerter {
    pub fn spawn(cfg: AlertConfig) -> Self {
        let (tx, rx) = mpsc::channel(256);
        tokio::spawn(worker(cfg, rx));
        Self { tx }
    }

    pub fn consider(&self, ev: &Event) {
        if ev.whitelisted == Some(true) {
            return;
        }
        if matches!(
            ev.event,
            Kind::Disconnect | Kind::ConnectDropped | Kind::Heartbeat
        ) {
            return;
        }
        let _ = self.tx.try_send(ev.clone());
    }
}

#[derive(Serialize)]
struct WebhookBody<'a> {
    severity: Severity,
    message: String,
    timestamp: String,
    name: &'a str,
    event: &'a Event,
}

async fn worker(cfg: AlertConfig, mut rx: mpsc::Receiver<Event>) {
    let mut last: HashMap<IpAddr, Instant> = HashMap::new();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .ok();
    while let Some(ev) = rx.recv().await {
        let ip = crate::arp::ip_from_src(&ev.src);
        if let Some(ip) = ip {
            let now = Instant::now();
            if let Some(prev) = last.get(&ip) {
                if now.duration_since(*prev) < cfg.cooldown && ev.event != Kind::Password {
                    // Always let credential captures through; collapse the rest.
                    if !matches!(ev.event, Kind::Command) {
                        continue;
                    }
                }
            }
            last.insert(ip, now);
            if last.len() > 4096 {
                last.retain(|_, t| now.duration_since(*t) < cfg.cooldown * 2);
            }
        }
        let message = format_message(&ev);
        tracing::warn!(
            severity = ?ev.event.severity(),
            %message,
            "alert"
        );
        if let (Some(url), Some(client)) = (cfg.webhook.as_ref(), client.as_ref()) {
            let body = WebhookBody {
                severity: ev.event.severity(),
                message: message.clone(),
                timestamp: ev.ts.to_rfc3339(),
                name: &cfg.name,
                event: &ev,
            };
            if let Err(e) = client.post(url).json(&body).send().await {
                tracing::warn!(error = %e, "webhook failed");
            }
        }
        if let Some(addr) = cfg.syslog {
            let cef = format!(
                "CEF:0|honeypot|honeypot|{}|{}|{}|{}|src={} dst_port={} suser={}",
                env!("CARGO_PKG_VERSION"),
                ev.event.as_str(),
                message.replace('|', "/"),
                cef_severity(ev.event.severity()),
                ev.src,
                ev.dst_port,
                ev.user.as_deref().unwrap_or("-"),
            );
            let _ = send_syslog(addr, &cef).await;
        }
    }
}

fn format_message(ev: &Event) -> String {
    let mac = ev
        .mac
        .as_deref()
        .map(|m| format!(" mac={m}"))
        .unwrap_or_default();
    match ev.event {
        Kind::Password => format!(
            "{} login from {}{mac} user={} pass={}",
            ev.svc.to_ascii_uppercase(),
            ev.src,
            ev.user.as_deref().unwrap_or("?"),
            ev.pass.as_deref().unwrap_or("?"),
        ),
        Kind::Command => format!(
            "{} command from {}{mac}: {}",
            ev.svc.to_ascii_uppercase(),
            ev.src,
            ev.data.as_deref().unwrap_or("?")
        ),
        Kind::Scan => format!(
            "Port scan from {}{mac} {}",
            ev.src,
            ev.data.as_deref().unwrap_or("")
        ),
        _ => format!(
            "{} {} from {}{mac}",
            ev.svc.to_ascii_uppercase(),
            ev.event.as_str(),
            ev.src
        ),
    }
}

fn cef_severity(s: Severity) -> u8 {
    match s {
        Severity::Info => 3,
        Severity::Important => 5,
        Severity::Critical => 7,
    }
}

async fn send_syslog(addr: SocketAddr, msg: &str) -> std::io::Result<()> {
    // StingBox uses TCP syslog (CEF). Fall back to UDP if TCP is refused.
    if let Ok(Ok(mut tcp)) =
        tokio::time::timeout(Duration::from_secs(2), tokio::net::TcpStream::connect(addr)).await
    {
        tcp.write_all(msg.as_bytes()).await?;
        tcp.write_all(b"\n").await?;
        return Ok(());
    }
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.send_to(msg.as_bytes(), addr).await?;
    Ok(())
}

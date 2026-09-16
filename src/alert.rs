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

// The webhook body carries BOTH vocabularies on purpose. `severity`/`message`/
// `name`/`event` are the original fields, unchanged for existing consumers. The
// `level`/`title`/`description`/`source` set is what a generic relay reads (the
// estate's notify-relay renders exactly those into a Discord embed); without them
// every alert arrives as an empty "Notification" with no text.
#[derive(Serialize)]
struct WebhookBody<'a> {
    severity: Severity,
    message: String,
    timestamp: String,
    name: &'a str,
    event: &'a Event,
    level: &'static str,
    title: String,
    description: String,
    source: &'a str,
}

impl Severity {
    /// Generic relay vocabulary. Critical is the one that must page.
    pub fn level(self) -> &'static str {
        match self {
            Severity::Critical => "error",
            Severity::Important => "warn",
            Severity::Info => "info",
        }
    }
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
                level: ev.event.severity().level(),
                title: format!(
                    "{} {} on {}:{}",
                    cfg.name,
                    ev.event.as_str(),
                    ev.svc,
                    ev.dst_port
                ),
                description: message.clone(),
                source: &cfg.name,
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

#[cfg(test)]
mod webhook_body_tests {
    use super::*;
    use crate::event::{Event, Kind};
    use std::net::SocketAddr;

    fn body_json(kind: Kind) -> serde_json::Value {
        let src: SocketAddr = "192.168.50.14:4242".parse().unwrap();
        let ev = Event::new("ssh", 2222, src, kind);
        let message = format_message(&ev);
        let body = WebhookBody {
            severity: ev.event.severity(),
            message: message.clone(),
            timestamp: ev.ts.to_rfc3339(),
            name: "opie",
            event: &ev,
            level: ev.event.severity().level(),
            title: format!("{} {} on {}:{}", "opie", ev.event.as_str(), ev.svc, ev.dst_port),
            description: message,
            source: "opie",
        };
        serde_json::to_value(&body).expect("serializes")
    }

    #[test]
    fn carries_the_generic_relay_fields() {
        let v = body_json(Kind::Password);
        for f in ["level", "title", "description", "source"] {
            assert!(v.get(f).is_some(), "missing {f}: a relay renders an empty notification without it");
        }
        assert!(!v["title"].as_str().unwrap().is_empty(), "title must not be empty");
        assert!(!v["description"].as_str().unwrap().is_empty(), "description must not be empty");
        assert_eq!(v["source"], "opie");
    }

    #[test]
    fn keeps_the_original_fields() {
        let v = body_json(Kind::Scan);
        for f in ["severity", "message", "timestamp", "name", "event"] {
            assert!(v.get(f).is_some(), "removed pre-existing field {f}");
        }
    }

    #[test]
    fn severity_maps_to_relay_levels() {
        assert_eq!(Severity::Critical.level(), "error");
        assert_eq!(Severity::Important.level(), "warn");
        assert_eq!(Severity::Info.level(), "info");
        // and through a real event: a captured password must page, not inform.
        assert_eq!(body_json(Kind::Password)["level"], "error");
        assert_eq!(body_json(Kind::Scan)["level"], "warn");
        assert_eq!(body_json(Kind::Probe)["level"], "info");
    }
}

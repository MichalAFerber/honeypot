use chrono::{DateTime, Utc};
use serde::Serialize;
use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Connect,
    ConnectDropped,
    Probe,
    Password,
    Command,
    Disconnect,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Connect => "connect",
            Kind::ConnectDropped => "connect_dropped",
            Kind::Probe => "probe",
            Kind::Password => "password",
            Kind::Command => "command",
            Kind::Disconnect => "disconnect",
        }
    }
}

/// One JSONL object per honeypot event.
#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub ts: DateTime<Utc>,
    pub svc: &'static str,
    pub dst_port: u16,
    pub src: String,
    pub event: Kind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pass: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ua: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<usize>,
}

impl Event {
    pub fn new(svc: &'static str, dst_port: u16, src: SocketAddr, event: Kind) -> Self {
        Self {
            ts: Utc::now(),
            svc,
            dst_port,
            src: src.to_string(),
            event,
            user: None,
            pass: None,
            client: None,
            method: None,
            path: None,
            ua: None,
            data: None,
            bytes: None,
        }
    }

    pub fn user(mut self, v: impl Into<String>) -> Self {
        self.user = Some(v.into());
        self
    }

    pub fn pass(mut self, v: impl Into<String>) -> Self {
        self.pass = Some(v.into());
        self
    }

    pub fn client(mut self, v: impl Into<String>) -> Self {
        self.client = Some(v.into());
        self
    }

    pub fn method(mut self, v: impl Into<String>) -> Self {
        self.method = Some(v.into());
        self
    }

    pub fn path(mut self, v: impl Into<String>) -> Self {
        self.path = Some(v.into());
        self
    }

    pub fn ua(mut self, v: impl Into<String>) -> Self {
        self.ua = Some(v.into());
        self
    }

    pub fn data(mut self, v: impl Into<String>) -> Self {
        self.data = Some(v.into());
        self
    }

    pub fn bytes(mut self, n: usize) -> Self {
        self.bytes = Some(n);
        self
    }
}

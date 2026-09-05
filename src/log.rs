use crate::event::Event;
use anyhow::Context;
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Non-blocking event emitter. A single writer task appends JSONL.
#[derive(Clone)]
pub struct EventLog {
    tx: mpsc::Sender<Event>,
}

impl EventLog {
    pub fn spawn_file(path: PathBuf) -> anyhow::Result<(Self, JoinHandle<()>)> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("create log dir {}", parent.display()))?;
            }
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("open log file {}", path.display()))?;
        let (tx, rx) = mpsc::channel(1024);
        let handle = tokio::spawn(writer(rx, file));
        Ok((Self { tx }, handle))
    }

    pub fn channel(capacity: usize) -> (Self, mpsc::Receiver<Event>) {
        let (tx, rx) = mpsc::channel(capacity);
        (Self { tx }, rx)
    }

    pub fn emit(&self, ev: Event) {
        tracing::info!(
            svc = ev.svc,
            dst_port = ev.dst_port,
            src = %ev.src,
            event = ev.event.as_str(),
            user = ev.user.as_deref(),
            "honeypot"
        );
        if self.tx.try_send(ev).is_err() {
            tracing::warn!("event log full; dropping event");
        }
    }
}

async fn writer(mut rx: mpsc::Receiver<Event>, file: std::fs::File) {
    let mut file = tokio::fs::File::from_std(file);
    while let Some(ev) = rx.recv().await {
        match serde_json::to_string(&ev) {
            Ok(line) => {
                if file.write_all(line.as_bytes()).await.is_err() {
                    break;
                }
                if file.write_all(b"\n").await.is_err() {
                    break;
                }
            }
            Err(e) => tracing::error!(error = %e, "serialize event"),
        }
    }
    let _ = file.flush().await;
}

use crate::event::{Event, Kind};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

type Hits = HashMap<IpAddr, Vec<(Instant, u16)>>;

/// If one IP hits several decoy ports in a short window, emit a `scan` event.
#[derive(Clone)]
pub struct ScanWatch {
    inner: Arc<Mutex<Hits>>,
    window: Duration,
    threshold: usize,
}

impl ScanWatch {
    pub fn new(window: Duration, threshold: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            window,
            threshold: threshold.max(2),
        }
    }

    pub fn disabled() -> Self {
        Self::new(Duration::from_secs(0), usize::MAX)
    }

    pub fn observe(&self, ev: &Event) -> Option<Event> {
        if self.window.is_zero() {
            return None;
        }
        if !matches!(ev.event, Kind::Connect | Kind::Probe) {
            return None;
        }
        let ip = crate::arp::ip_from_src(&ev.src)?;
        let now = Instant::now();
        let mut map = self.inner.lock().ok()?;
        if map.len() > 4096 {
            map.retain(|_, hits| {
                hits.retain(|(t, _)| now.duration_since(*t) < self.window);
                !hits.is_empty()
            });
        }
        let hits = map.entry(ip).or_default();
        hits.retain(|(t, _)| now.duration_since(*t) < self.window);
        if !hits.iter().any(|(_, p)| *p == ev.dst_port) {
            hits.push((now, ev.dst_port));
        }
        if hits.len() >= self.threshold {
            let ports: Vec<String> = hits.iter().map(|(_, p)| p.to_string()).collect();
            let mut scan = Event::new(ev.svc, ev.dst_port, ev.src.parse().ok()?, Kind::Scan);
            scan.src = ev.src.clone();
            scan.data = Some(format!("ports={}", ports.join(",")));
            scan.mac = ev.mac.clone();
            hits.clear();
            return Some(scan);
        }
        None
    }
}

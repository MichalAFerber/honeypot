use std::net::IpAddr;

/// Best-effort MAC from the kernel ARP table. Only works on Linux and only for
/// L2-local peers (the StingBox LAN case). Returns None on macOS/tests.
pub fn lookup(ip: IpAddr) -> Option<String> {
    let want = ip.to_string();
    let text = std::fs::read_to_string("/proc/net/arp").ok()?;
    for line in text.lines().skip(1) {
        let mut cols = line.split_whitespace();
        let Some(addr) = cols.next() else { continue };
        if addr != want {
            continue;
        }
        let hw = cols.nth(2)?;
        if hw == "00:00:00:00:00:00" {
            return None;
        }
        return Some(hw.to_ascii_lowercase());
    }
    None
}

pub fn ip_from_src(src: &str) -> Option<IpAddr> {
    src.parse::<std::net::SocketAddr>()
        .ok()
        .map(|s| s.ip())
        .or_else(|| src.parse().ok())
}

use clap::Parser;
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "honeypot",
    about = "LAN intrusion alarm (StingBox-style). Logs probes; never executes attacker input.",
    version
)]
pub struct Args {
    /// Bind address (no port)
    #[arg(short, long, default_value = "0.0.0.0")]
    pub bind: IpAddr,

    /// JSONL event log path
    #[arg(short, long, default_value = "events.jsonl")]
    pub log: PathBuf,

    /// Concurrent connection cap across all services
    #[arg(long, default_value_t = 64)]
    pub max_connections: usize,

    /// Per-read timeout in seconds
    #[arg(long, default_value_t = 10)]
    pub read_timeout_secs: u64,

    /// Idle timeout for line-oriented sessions
    #[arg(long, default_value_t = 15)]
    pub idle_timeout_secs: u64,

    /// Tokio worker threads (Pi Zero 2W has 4 cores)
    #[arg(long, default_value_t = 4)]
    pub workers: usize,

    /// Banner jitter minimum milliseconds
    #[arg(long, default_value_t = 20)]
    pub jitter_min_ms: u64,

    /// Banner jitter maximum milliseconds
    #[arg(long, default_value_t = 120)]
    pub jitter_max_ms: u64,

    #[arg(long, default_value_t = 22)]
    pub ssh_port: u16,
    #[arg(long, default_value_t = 23)]
    pub telnet_port: u16,
    #[arg(long, default_value_t = 21)]
    pub ftp_port: u16,
    #[arg(long, default_value_t = 80)]
    pub http_port: u16,
    /// Set 0 to disable the alternate HTTP port
    #[arg(long, default_value_t = 8080)]
    pub http_alt_port: u16,
    #[arg(long, default_value_t = 554)]
    pub rtsp_port: u16,
    #[arg(long, default_value_t = 6379)]
    pub redis_port: u16,
    #[arg(long, default_value_t = 3389)]
    pub rdp_port: u16,
    #[arg(long, default_value_t = 445)]
    pub smb_port: u16,

    /// POST JSON alerts here (Discord/ntfy/Herald). HTTPS allowed.
    #[arg(long)]
    pub webhook: Option<String>,

    /// Syslog CEF destination, host:port (TCP then UDP)
    #[arg(long)]
    pub syslog: Option<String>,

    /// Collapse repeat alerts from the same IP (StingBox default is 10 minutes)
    #[arg(long, default_value_t = 600)]
    pub alert_cooldown_secs: u64,

    /// Name included in webhook/syslog payloads
    #[arg(long, default_value = "honeypot")]
    pub name: String,

    /// Do not alert on these source IPs (scanners you own)
    #[arg(long = "allow-ip")]
    pub allow_ip: Vec<IpAddr>,

    /// Persist the decoy SSH host key (stable fingerprint)
    #[arg(long)]
    pub ssh_host_key: Option<PathBuf>,

    /// Seconds between heartbeat log lines. 0 disables.
    #[arg(long, default_value_t = 300)]
    pub heartbeat_secs: u64,

    #[arg(long)]
    pub no_ssh: bool,
    #[arg(long)]
    pub no_telnet: bool,
    #[arg(long)]
    pub no_ftp: bool,
    #[arg(long)]
    pub no_http: bool,
    #[arg(long)]
    pub no_rtsp: bool,
    #[arg(long)]
    pub no_redis: bool,
    #[arg(long)]
    pub no_rdp: bool,
    #[arg(long)]
    pub no_smb: bool,
}

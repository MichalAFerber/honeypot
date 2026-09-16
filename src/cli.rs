use crate::webhook::WebhookUrl;
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
    ///
    /// Typically carries a credential in its query string, so it is a
    /// `WebhookUrl`, which redacts itself when formatted.
    #[arg(long, env = "HONEYPOT_WEBHOOK", hide_env_values = true)]
    pub webhook: Option<WebhookUrl>,

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

#[cfg(test)]
mod webhook_env_tests {
    use super::*;
    use clap::CommandFactory;

    // §16: the webhook URL (which carries the notify token) must never show
    // up in --help just because HONEYPOT_WEBHOOK is set in the environment.
    #[test]
    fn webhook_env_value_is_hidden_from_help() {
        let sentinel = "https://example.invalid/S3CRET-SENTINEL-TOKEN";
        std::env::set_var("HONEYPOT_WEBHOOK", sentinel);
        let help = Args::command().render_long_help().to_string();
        std::env::remove_var("HONEYPOT_WEBHOOK");

        assert!(
            !help.contains(sentinel),
            "help leaked the HONEYPOT_WEBHOOK value:\n{help}"
        );
        assert!(
            help.contains("HONEYPOT_WEBHOOK"),
            "help should still name the HONEYPOT_WEBHOOK variable:\n{help}"
        );
    }

    // `Args` derives Debug, so anything that debug-formats it prints every
    // field. The webhook URL carries the notify token, so it must not be one of
    // the readable ones.
    #[test]
    fn debug_of_args_hides_the_webhook_value() {
        use clap::Parser as _;
        let token = "ARGSDEBUGSENTINEL0123456789";
        let args = Args::parse_from([
            "honeypot",
            "--webhook",
            &format!("https://relay.example.invalid/hook?token={token}"),
        ]);

        let rendered = format!("{args:?}");
        assert!(
            !rendered.contains(token),
            "Debug for Args leaked the webhook token: {rendered}"
        );
        assert!(
            rendered.contains("relay.example.invalid"),
            "Debug for Args should still name the webhook host: {rendered}"
        );
    }
}

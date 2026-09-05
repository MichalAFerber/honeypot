pub mod cli;
pub mod event;
pub mod log;
pub mod net;
pub mod services;
pub mod util;

use crate::cli::Args;
use crate::log::EventLog;
use crate::net::App;
use crate::services::{spawn_service, Service};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

pub async fn run(args: Args) -> anyhow::Result<()> {
    let (log, writer) = EventLog::spawn_file(args.log.clone())?;
    let app = App {
        log,
        cap: Arc::new(Semaphore::new(args.max_connections.max(1))),
        read_timeout: Duration::from_secs(args.read_timeout_secs.max(1)),
        idle_timeout: Duration::from_secs(args.idle_timeout_secs.max(1)),
        max_read: 4096,
        max_lines: 32,
        jitter_ms: (args.jitter_min_ms, args.jitter_max_ms),
    };

    let mut services = Vec::new();
    if !args.no_ssh && args.ssh_port != 0 {
        services.push(Service::Ssh {
            port: args.ssh_port,
        });
    }
    if !args.no_telnet && args.telnet_port != 0 {
        services.push(Service::Telnet {
            port: args.telnet_port,
        });
    }
    if !args.no_ftp && args.ftp_port != 0 {
        services.push(Service::Ftp {
            port: args.ftp_port,
        });
    }
    if !args.no_http && args.http_port != 0 {
        services.push(Service::Http {
            port: args.http_port,
        });
    }
    if !args.no_http && args.http_alt_port != 0 {
        services.push(Service::Http {
            port: args.http_alt_port,
        });
    }
    if !args.no_rtsp && args.rtsp_port != 0 {
        services.push(Service::Rtsp {
            port: args.rtsp_port,
        });
    }
    if !args.no_redis && args.redis_port != 0 {
        services.push(Service::Redis {
            port: args.redis_port,
        });
    }
    if !args.no_rdp && args.rdp_port != 0 {
        services.push(Service::Rdp {
            port: args.rdp_port,
        });
    }

    if services.is_empty() {
        anyhow::bail!("all services disabled");
    }

    let bind = args.bind;
    let mut handles = Vec::new();
    for svc in services {
        let app = app.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = spawn_service(bind, svc, app).await {
                tracing::error!(error = %e, "service failed");
            }
        }));
    }

    tracing::info!(
        bind = %bind,
        log = %args.log.display(),
        max_connections = args.max_connections,
        "honeypot running; Ctrl-C to stop"
    );

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutdown requested");
    for h in handles {
        h.abort();
    }
    drop(app);
    let _ = tokio::time::timeout(Duration::from_secs(2), writer).await;
    Ok(())
}

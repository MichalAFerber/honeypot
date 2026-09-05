use clap::Parser;
use honeypot::cli::Args;
use tracing_subscriber::EnvFilter;

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let workers = args.workers.clamp(1, 4);

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .compact()
        .init();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()?;

    runtime.block_on(honeypot::run(args))
}

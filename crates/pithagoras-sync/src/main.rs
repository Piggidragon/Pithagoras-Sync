use std::process::ExitCode;

use clap::Parser;
use pithagoras_sync::cli::{Cli, Cmd};

fn main() -> ExitCode {
    // The exec shim is this same program; it must start before anything else
    // (no runtime, no threads) because it sets up a process tree.
    if std::env::args_os().nth(1).as_deref() == Some(sync_ops::SHIM_ARG.as_ref()) {
        let spec = std::env::args().nth(2).unwrap_or_default();
        std::process::exit(sync_ops::shim_main(&spec));
    }
    let cli = Cli::parse();
    let level = if cli.verbose {
        tracing::Level::DEBUG
    } else if matches!(cli.cmd, Cmd::Run { .. }) {
        tracing::Level::INFO
    } else {
        tracing::Level::WARN
    };
    tracing_subscriber::fmt()
        .with_writer(pithagoras_sync::secrets::LogWriter)
        .with_max_level(level)
        .with_target(false)
        .init();
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("pithagoras-sync: {e}");
            return ExitCode::from(1);
        }
    };
    match rt.block_on(pithagoras_sync::cli::run(cli)) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("pithagoras-sync: {e}");
            ExitCode::from(1)
        }
    }
}

use std::io::IsTerminal;
use std::process::ExitCode;

use clap::Parser;
use pithagoras_sync::cli::{Cli, Cmd, link_argument};

fn main() -> ExitCode {
    // The exec shim is this same program; it must start before anything else
    // (no runtime, no threads) because it sets up a process tree.
    if std::env::args_os().nth(1).as_deref() == Some(sync_ops::SHIM_ARG.as_ref()) {
        std::process::exit(sync_ops::shim_main());
    }
    // A pairing link alone is what a browser hands over: the graphical flow
    // takes it (after asking), and no link is read as a command.
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let cli = match link_argument(&args) {
        Some(link) => Cli {
            verbose: false,
            cmd: Some(Cmd::Gui {
                link: Some(link),
                link_option: None,
            }),
        },
        None => Cli::parse(),
    };
    // The short commands die quietly when their output is cut off (`| head`), as
    // command line tools do; the client itself and the graphical flow keep
    // ignoring SIGPIPE.
    #[cfg(unix)]
    if !matches!(cli.cmd, Some(Cmd::Run { .. } | Cmd::Gui { .. })) {
        // SAFETY: resets one signal's disposition before any thread starts.
        unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    }
    let level = if cli.verbose {
        tracing::Level::DEBUG
    } else if matches!(cli.cmd, Some(Cmd::Run { .. })) {
        tracing::Level::INFO
    } else {
        tracing::Level::WARN
    };
    tracing_subscriber::fmt()
        .with_writer(pithagoras_sync::secrets::LogWriter)
        .with_max_level(level)
        .with_target(false)
        // Colours only for a terminal: a log file or the journal gets plain text.
        .with_ansi(
            std::io::stderr().is_terminal() && !matches!(cli.cmd, Some(Cmd::Run { detach: true })),
        )
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

mod audit;
mod color;
mod detail;
mod follow;
mod hexdump;
mod issues;
mod stats;
mod summary;
mod timestamp;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "fireshark")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Summary {
        path: PathBuf,
        #[arg(short = 'f', long = "filter", help = "Display filter expression")]
        filter: Option<String>,
        #[arg(long = "backend", default_value = "native")]
        backend: String,
    },
    Detail {
        path: PathBuf,
        #[arg(help = "Packet number (1-indexed)")]
        packet: usize,
        #[arg(long = "backend", default_value = "native")]
        backend: String,
    },
    Stats {
        path: PathBuf,
        #[arg(long = "backend", default_value = "native")]
        backend: String,
    },
    Issues {
        path: PathBuf,
        #[arg(long = "backend", default_value = "native")]
        backend: String,
    },
    Audit {
        path: PathBuf,
        #[arg(long = "backend", default_value = "native")]
        backend: String,
    },
    Follow {
        path: PathBuf,
        #[arg(help = "Stream ID")]
        stream: u32,
        #[arg(long = "backend", default_value = "native")]
        backend: String,
    },
}

fn require_native_backend(
    backend: &str,
    command_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if backend != "native" {
        return Err(
            format!("backend '{backend}' does not support the '{command_name}' command").into(),
        );
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Command::Summary {
            path,
            filter,
            backend,
        } => summary::run(&path, filter.as_deref(), &backend)?,
        Command::Detail {
            path,
            packet,
            backend,
        } => {
            require_native_backend(&backend, "detail")?;
            detail::run(&path, packet)?;
        }
        Command::Stats { path, backend } => stats::run(&path, &backend)?,
        Command::Issues { path, backend } => {
            require_native_backend(&backend, "issues")?;
            issues::run(&path)?;
        }
        Command::Audit { path, backend } => {
            require_native_backend(&backend, "audit")?;
            audit::run(&path)?;
        }
        Command::Follow {
            path,
            stream,
            backend,
        } => {
            require_native_backend(&backend, "follow")?;
            follow::run(&path, stream)?;
        }
    }

    Ok(())
}

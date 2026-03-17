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
    },
    Detail {
        path: PathBuf,
        #[arg(help = "Packet number (1-indexed)")]
        packet: usize,
    },
    Stats {
        path: PathBuf,
    },
    Issues {
        path: PathBuf,
    },
    Audit {
        path: PathBuf,
    },
    Follow {
        path: PathBuf,
        #[arg(help = "Stream ID")]
        stream: u32,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Command::Summary { path, filter } => summary::run(&path, filter.as_deref())?,
        Command::Detail { path, packet } => detail::run(&path, packet)?,
        Command::Stats { path } => stats::run(&path)?,
        Command::Issues { path } => issues::run(&path)?,
        Command::Audit { path } => audit::run(&path)?,
        Command::Follow { path, stream } => follow::run(&path, stream)?,
    }

    Ok(())
}

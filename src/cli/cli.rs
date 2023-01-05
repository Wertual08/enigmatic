use std::path::PathBuf;

use clap::{Parser};

use super::CliCommand;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Sets a custom storage locatin
    #[arg(short, long, value_name = "FILE")]
    pub storage: Option<PathBuf>,

    /// Turn debugging information on
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub debug: u8,

    #[command(subcommand)]
    pub command: CliCommand,
}
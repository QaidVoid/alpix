use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(author, version)]
#[command(arg_required_else_help = true)]
pub struct Args {
    /// Unimplemented
    #[arg(short, long)]
    pub verbose: bool,

    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Patch and generate self-extracting package
    #[command(arg_required_else_help = true)]
    #[clap(name = "install", visible_alias = "i", alias = "add")]
    Generate {
        /// Packages to generate
        #[arg(required = true)]
        packages: Vec<String>,
    }
}

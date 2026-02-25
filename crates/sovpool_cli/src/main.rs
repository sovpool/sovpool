use clap::Parser;

mod assess;
mod pool;

/// sovpool — Bitcoin CTV payment pool toolkit
#[derive(Parser)]
#[command(name = "sovpool", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Sovereignty assessment for Bitcoin protocols
    Assess(assess::AssessArgs),
    /// CTV payment pool operations
    Pool(pool::PoolArgs),
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Assess(args) => assess::run(args),
        Commands::Pool(args) => pool::run(args),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

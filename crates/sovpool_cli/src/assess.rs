use clap::Args;
use sovpool_assess::protocols::*;
use sovpool_assess::{ComparisonReport, SovereigntyAssessable};

#[derive(Args)]
pub struct AssessArgs {
    #[command(subcommand)]
    command: AssessCommand,
}

#[derive(clap::Subcommand)]
enum AssessCommand {
    /// Assess a single protocol
    Report {
        /// Protocol to assess: l1, lightning, ark, cashu, ctv-pool
        protocol: String,

        /// Output format: markdown, json
        #[arg(short, long, default_value = "markdown")]
        format: String,
    },
    /// Compare multiple protocols side-by-side
    Compare {
        /// Protocols to compare (comma-separated or 'all')
        #[arg(default_value = "all")]
        protocols: String,

        /// Output format: markdown, json
        #[arg(short, long, default_value = "markdown")]
        format: String,
    },
}

fn get_protocol(name: &str) -> Result<Box<dyn SovereigntyAssessable>, String> {
    match name.to_lowercase().as_str() {
        "l1" | "bitcoin" | "bitcoin-l1" => Ok(Box::new(BitcoinL1)),
        "lightning" | "ln" => Ok(Box::new(Lightning)),
        "ark" | "arkade" => Ok(Box::new(Ark)),
        "cashu" | "ecash" => Ok(Box::new(Cashu)),
        "ctv-pool" | "ctv_pool" | "ctvpool" | "pool" => Ok(Box::new(CtvPool)),
        _ => Err(format!(
            "unknown protocol: {name}. Valid: l1, lightning, ark, cashu, ctv-pool"
        )),
    }
}

fn all_protocols() -> Vec<Box<dyn SovereigntyAssessable>> {
    vec![
        Box::new(BitcoinL1),
        Box::new(Lightning),
        Box::new(Ark),
        Box::new(Cashu),
        Box::new(CtvPool),
    ]
}

pub fn run(args: AssessArgs) -> Result<(), String> {
    match args.command {
        AssessCommand::Report { protocol, format } => {
            let proto = get_protocol(&protocol)?;
            let report = proto.assess();

            match format.as_str() {
                "json" => {
                    println!("{}", report.to_json().map_err(|e| e.to_string())?);
                }
                "markdown" | "md" => {
                    println!("{}", report.to_markdown());
                }
                _ => return Err(format!("unknown format: {format}. Valid: markdown, json")),
            }
        }
        AssessCommand::Compare { protocols, format } => {
            let protos: Vec<Box<dyn SovereigntyAssessable>> = if protocols == "all" {
                all_protocols()
            } else {
                protocols
                    .split(',')
                    .map(|s| get_protocol(s.trim()))
                    .collect::<Result<Vec<_>, _>>()?
            };

            let reports = protos.iter().map(|p| p.assess()).collect();
            let comparison = ComparisonReport::new(reports);

            match format.as_str() {
                "json" => {
                    println!("{}", comparison.to_json().map_err(|e| e.to_string())?);
                }
                "markdown" | "md" => {
                    println!("{}", comparison.to_markdown());
                }
                _ => return Err(format!("unknown format: {format}. Valid: markdown, json")),
            }
        }
    }

    Ok(())
}

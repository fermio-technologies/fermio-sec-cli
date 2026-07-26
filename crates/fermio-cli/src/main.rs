use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use fermio_core::Severity;
use fermio_engine::ScanEngine;
use fermio_language_php::PhpFrontend;
use fermio_report::{write_report, OutputFormat};
use fermio_rules::built_in_rules;
use std::{fs::File, io, path::PathBuf};

#[derive(Debug, Parser)]
#[command(
    name = "fermio-sec",
    version,
    about = "Fermio local-first static analysis CLI"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Scan {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = FormatArg::Terminal)]
        format: FormatArg,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long, value_enum)]
        fail_on: Option<SeverityArg>,
        #[arg(long)]
        include_vendor: bool,
    },
    Languages,
    Frameworks,
    Rules,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FormatArg {
    Terminal,
    Json,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SeverityArg {
    Low,
    Medium,
    High,
    Critical,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(2);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Scan {
            path,
            format,
            output,
            fail_on,
            include_vendor,
        } => {
            let engine = ScanEngine::new(vec![Box::new(PhpFrontend::new())], built_in_rules());
            let result = engine.scan(&path, include_vendor)?;
            let output_format = match format {
                FormatArg::Terminal => OutputFormat::Terminal,
                FormatArg::Json => OutputFormat::Json,
            };

            if let Some(path) = output {
                let file = File::create(&path)
                    .with_context(|| format!("failed to create {}", path.display()))?;
                write_report(&result, output_format, file)?;
            } else {
                write_report(&result, output_format, io::stdout().lock())?;
            }

            if let Some(threshold) = fail_on.map(Severity::from) {
                if result
                    .findings
                    .iter()
                    .any(|finding| finding.severity >= threshold)
                {
                    std::process::exit(1);
                }
            }
        }
        Command::Languages => println!("php\tenabled\tbuilt-in"),
        Command::Frameworks => {
            println!("laravel\tenabled");
            println!("symfony\tenabled");
            println!("wordpress\tenabled");
        }
        Command::Rules => {
            for rule in built_in_rules() {
                println!("{}", rule.id());
            }
        }
    }

    Ok(())
}

impl From<SeverityArg> for Severity {
    fn from(value: SeverityArg) -> Self {
        match value {
            SeverityArg::Low => Severity::Low,
            SeverityArg::Medium => Severity::Medium,
            SeverityArg::High => Severity::High,
            SeverityArg::Critical => Severity::Critical,
        }
    }
}

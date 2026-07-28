use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use fermio_core::{FindingBaseline, Severity};
use fermio_engine::{ScanEngine, ScanOptions};
use fermio_language_php::PhpFrontend;
use fermio_report::{write_report, OutputFormat};
use fermio_rules::built_in_rules;
use std::{
    fs,
    fs::File,
    io,
    path::{Path, PathBuf},
};

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
        #[arg(long, default_value_t = 100_000)]
        max_files: usize,
        #[arg(long, default_value_t = 2 * 1024 * 1024)]
        max_file_size: u64,
        #[arg(long, value_name = "FILE", conflicts_with = "write_baseline")]
        baseline: Option<PathBuf>,
        #[arg(long, value_name = "FILE", conflicts_with = "baseline")]
        write_baseline: Option<PathBuf>,
    },
    Languages,
    Frameworks,
    Rules,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FormatArg {
    Terminal,
    Json,
    Sarif,
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
            max_files,
            max_file_size,
            baseline,
            write_baseline,
        } => {
            let engine = ScanEngine::new(vec![Box::new(PhpFrontend::new())], built_in_rules());
            let mut result = engine.scan_with_options(
                &path,
                ScanOptions {
                    include_vendor,
                    max_files,
                    max_file_size,
                },
            )?;

            if let Some(path) = write_baseline {
                write_baseline_file(&path, &FindingBaseline::from_result(&result))?;
            }

            if let Some(path) = baseline {
                let baseline = read_baseline_file(&path)?;
                baseline.apply(&mut result);
            }

            let output_format = match format {
                FormatArg::Terminal => OutputFormat::Terminal,
                FormatArg::Json => OutputFormat::Json,
                FormatArg::Sarif => OutputFormat::Sarif,
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

fn read_baseline_file(path: &Path) -> Result<FindingBaseline> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read baseline {}", path.display()))?;
    let baseline: FindingBaseline = serde_json::from_str(&content)
        .with_context(|| format!("invalid baseline JSON in {}", path.display()))?;
    if baseline.schema_version != FindingBaseline::SCHEMA_VERSION {
        bail!(
            "unsupported baseline schema version {} in {}; expected {}",
            baseline.schema_version,
            path.display(),
            FindingBaseline::SCHEMA_VERSION
        );
    }
    Ok(baseline)
}

fn write_baseline_file(path: &Path, baseline: &FindingBaseline) -> Result<()> {
    let file = File::create(path)
        .with_context(|| format!("failed to create baseline {}", path.display()))?;
    serde_json::to_writer_pretty(file, baseline)
        .with_context(|| format!("failed to write baseline {}", path.display()))?;
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

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use fermio_config::{load_for_root, FermioConfig};
use fermio_core::{FindingBaseline, ScanResult, Severity};
use fermio_engine::{ScanEngine, ScanOptions};
use fermio_language_php::PhpFrontend;
use fermio_report::{write_report, OutputFormat};
use fermio_rules::{built_in_rules, Rule};
use fermio_rules_php_oo::built_in_rules as built_in_php_oo_rules;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    fs::File,
    io,
    path::{Path, PathBuf},
};

const DEFAULT_MAX_FILES: usize = 100_000;
const DEFAULT_MAX_FILE_SIZE: u64 = 2 * 1024 * 1024;

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
        #[arg(long)]
        max_files: Option<usize>,
        #[arg(long)]
        max_file_size: Option<u64>,
        #[arg(long, value_name = "FILE", conflicts_with = "no_config")]
        config: Option<PathBuf>,
        #[arg(long, conflicts_with = "config")]
        no_config: bool,
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
            config,
            no_config,
            baseline,
            write_baseline,
        } => {
            let loaded_config = load_for_root(&path, config.as_deref(), no_config)?;
            let configured_rules = select_rules(&loaded_config.config)?;
            let scan_config = &loaded_config.config.scan;

            let include_vendor = include_vendor || scan_config.include_vendor.unwrap_or(false);
            let max_files = max_files
                .or(scan_config.max_files)
                .unwrap_or(DEFAULT_MAX_FILES);
            let max_file_size = max_file_size
                .or(scan_config.max_file_size)
                .unwrap_or(DEFAULT_MAX_FILE_SIZE);
            let fail_on = fail_on.map(Severity::from).or(scan_config.fail_on);
            let configured_baseline = scan_config
                .baseline
                .as_deref()
                .map(|path| loaded_config.resolve_path(path));
            let baseline = if write_baseline.is_some() {
                baseline
            } else {
                baseline.or(configured_baseline)
            };

            let engine = ScanEngine::new(vec![Box::new(PhpFrontend::new())], configured_rules);
            let mut result = engine.scan_with_options(
                &path,
                ScanOptions {
                    include_vendor,
                    max_files,
                    max_file_size,
                },
            )?;

            apply_severity_overrides(&mut result, &loaded_config.config.rules.severity);

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

            if let Some(threshold) = fail_on {
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
            for rule in registered_rules() {
                println!("{}", rule.id());
            }
        }
    }

    Ok(())
}

fn registered_rules() -> Vec<Box<dyn Rule>> {
    let mut rules = built_in_rules();
    rules.extend(built_in_php_oo_rules());
    rules
}

fn select_rules(config: &FermioConfig) -> Result<Vec<Box<dyn Rule>>> {
    let rules = registered_rules();
    let known = rules
        .iter()
        .map(|rule| rule.id())
        .collect::<BTreeSet<_>>();

    let mut referenced = Vec::new();
    if let Some(enabled) = &config.rules.enabled {
        referenced.extend(enabled.iter().map(String::as_str));
    }
    referenced.extend(config.rules.disabled.iter().map(String::as_str));
    referenced.extend(config.rules.severity.keys().map(String::as_str));

    for rule_id in referenced {
        if !known.contains(rule_id) {
            bail!("configuration references unknown rule `{rule_id}`");
        }
    }

    let enabled = config.rules.enabled.as_ref().map(|values| {
        values
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
    });
    let disabled = config
        .rules
        .disabled
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();

    Ok(rules
        .into_iter()
        .filter(|rule| {
            enabled
                .as_ref()
                .is_none_or(|selected| selected.contains(rule.id()))
                && !disabled.contains(rule.id())
        })
        .collect())
}

fn apply_severity_overrides(result: &mut ScanResult, overrides: &BTreeMap<String, Severity>) {
    for finding in &mut result.findings {
        if let Some(severity) = overrides.get(&finding.rule_id) {
            finding.severity = *severity;
        }
    }
    result.findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| left.location.path.cmp(&right.location.path))
            .then_with(|| left.location.start_line.cmp(&right.location.start_line))
    });
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

#[cfg(test)]
mod tests {
    use super::*;
    use fermio_config::parse;
    use fermio_core::{Confidence, Finding, SourceLocation};

    #[test]
    fn filters_registered_rules_from_configuration() {
        let config = parse(
            r#"
                [rules]
                enabled = ["FERMIO-PHP-CORE-EVAL-001", "FERMIO-PHP-TAINT-SQL-OO-001"]
                disabled = ["FERMIO-PHP-CORE-EVAL-001"]
            "#,
        );
        assert!(config.is_err(), "conflicting rule selection should fail early");

        let config = parse(
            r#"
                [rules]
                enabled = ["FERMIO-PHP-CORE-EVAL-001", "FERMIO-PHP-TAINT-SQL-OO-001"]
            "#,
        )
        .expect("configuration should parse");
        let selected = select_rules(&config).expect("rule selection should succeed");
        let ids = selected.iter().map(|rule| rule.id()).collect::<BTreeSet<_>>();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains("FERMIO-PHP-CORE-EVAL-001"));
        assert!(ids.contains("FERMIO-PHP-TAINT-SQL-OO-001"));
    }

    #[test]
    fn rejects_unknown_rule_identifiers() {
        let config = parse(
            r#"
                [rules]
                disabled = ["FERMIO-UNKNOWN-001"]
            "#,
        )
        .expect("configuration syntax should parse");
        let error = select_rules(&config)
            .err()
            .expect("unknown rules must fail");
        assert!(error.to_string().contains("unknown rule"));
    }

    #[test]
    fn applies_severity_overrides_without_changing_fingerprint() {
        let mut result = ScanResult {
            project: fermio_core::ProjectMetadata {
                root: ".".into(),
                languages: vec!["php".to_string()],
                frameworks: Vec::new(),
            },
            statistics: fermio_core::ScanStatistics {
                findings: 1,
                ..fermio_core::ScanStatistics::default()
            },
            diagnostics: Vec::new(),
            findings: vec![Finding {
                rule_id: "FERMIO-PHP-CORE-EVAL-001".to_string(),
                title: "Example".to_string(),
                description: "Example".to_string(),
                severity: Severity::High,
                confidence: Confidence::High,
                location: SourceLocation {
                    path: "example.php".into(),
                    start_line: 1,
                    start_column: 1,
                    end_line: 1,
                    end_column: 5,
                },
                fingerprint: "stable".to_string(),
                cwe: None,
                framework: None,
                dataflow: Vec::new(),
            }],
        };
        let overrides = BTreeMap::from([(
            "FERMIO-PHP-CORE-EVAL-001".to_string(),
            Severity::Critical,
        )]);

        apply_severity_overrides(&mut result, &overrides);
        assert_eq!(result.findings[0].severity, Severity::Critical);
        assert_eq!(result.findings[0].fingerprint, "stable");
    }
}

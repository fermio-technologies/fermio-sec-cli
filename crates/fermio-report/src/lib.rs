use anyhow::Result;
use fermio_core::ScanResult;
use std::io::Write;

#[derive(Debug, Clone, Copy)]
pub enum OutputFormat {
    Terminal,
    Json,
}

pub fn write_report(
    result: &ScanResult,
    format: OutputFormat,
    mut writer: impl Write,
) -> Result<()> {
    match format {
        OutputFormat::Json => {
            serde_json::to_writer_pretty(&mut writer, result)?;
            writeln!(writer)?;
        }
        OutputFormat::Terminal => {
            writeln!(writer, "Fermio Security scan")?;
            writeln!(writer, "Root: {}", result.project.root.display())?;
            writeln!(writer, "Languages: {}", result.project.languages.join(", "))?;
            writeln!(writer, "Frameworks: {}", display_frameworks(&result.project.frameworks))?;
            writeln!(writer, "Files parsed: {}", result.statistics.files_parsed)?;
            writeln!(writer, "Findings: {}\n", result.statistics.findings)?;

            for finding in &result.findings {
                writeln!(
                    writer,
                    "{:?} {} {}:{}:{}",
                    finding.severity,
                    finding.rule_id,
                    finding.location.path.display(),
                    finding.location.start_line,
                    finding.location.start_column,
                )?;
                writeln!(writer, "  {}", finding.title)?;
                writeln!(writer, "  {}\n", finding.description)?;
            }
        }
    }
    Ok(())
}

fn display_frameworks(frameworks: &[String]) -> String {
    if frameworks.is_empty() {
        "generic-php".to_string()
    } else {
        frameworks.join(", ")
    }
}

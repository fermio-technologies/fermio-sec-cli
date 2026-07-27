use anyhow::Result;
use fermio_core::{Finding, ScanResult, Severity};
use serde_json::{json, Value};
use std::{collections::BTreeMap, io::Write};

#[derive(Debug, Clone, Copy)]
pub enum OutputFormat {
    Terminal,
    Json,
    Sarif,
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
        OutputFormat::Sarif => {
            serde_json::to_writer_pretty(&mut writer, &sarif_report(result))?;
            writeln!(writer)?;
        }
        OutputFormat::Terminal => {
            writeln!(writer, "Fermio Security scan")?;
            writeln!(writer, "Root: {}", result.project.root.display())?;
            writeln!(writer, "Languages: {}", result.project.languages.join(", "))?;
            writeln!(
                writer,
                "Frameworks: {}",
                display_frameworks(&result.project.frameworks)
            )?;
            writeln!(
                writer,
                "Files discovered: {}",
                result.statistics.files_discovered
            )?;
            writeln!(writer, "Files parsed: {}", result.statistics.files_parsed)?;
            writeln!(writer, "Files skipped: {}", result.statistics.files_skipped)?;
            writeln!(writer, "Diagnostics: {}", result.statistics.diagnostics)?;
            writeln!(
                writer,
                "Suppressed findings: {}",
                result.statistics.suppressed_findings
            )?;
            writeln!(writer, "Findings: {}\n", result.statistics.findings)?;

            for diagnostic in &result.diagnostics {
                if let Some(location) = &diagnostic.location {
                    writeln!(
                        writer,
                        "{:?} {} {}:{}:{}",
                        diagnostic.severity,
                        diagnostic.code,
                        location.path.display(),
                        location.start_line,
                        location.start_column,
                    )?;
                } else {
                    writeln!(writer, "{:?} {}", diagnostic.severity, diagnostic.code)?;
                }
                writeln!(writer, "  {}\n", diagnostic.message)?;
            }

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

fn sarif_report(result: &ScanResult) -> Value {
    let mut rules = BTreeMap::<String, (&str, &str, Option<&str>)>::new();
    for finding in &result.findings {
        rules.entry(finding.rule_id.clone()).or_insert((
            finding.title.as_str(),
            finding.description.as_str(),
            finding.cwe.as_deref(),
        ));
    }

    let rule_ids = rules.keys().cloned().collect::<Vec<_>>();
    let rule_indexes = rule_ids
        .iter()
        .enumerate()
        .map(|(index, rule_id)| (rule_id.as_str(), index))
        .collect::<BTreeMap<_, _>>();

    let sarif_rules = rule_ids
        .iter()
        .map(|rule_id| {
            let (title, description, cwe) = rules[rule_id];
            let mut properties = serde_json::Map::new();
            if let Some(cwe) = cwe {
                properties.insert("tags".to_string(), json!([cwe]));
            }
            json!({
                "id": rule_id,
                "name": rule_id,
                "shortDescription": { "text": title },
                "fullDescription": { "text": description },
                "properties": properties,
            })
        })
        .collect::<Vec<_>>();

    let results = result
        .findings
        .iter()
        .map(|finding| sarif_result(finding, rule_indexes[finding.rule_id.as_str()]))
        .collect::<Vec<_>>();

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "fermio-sec",
                    "informationUri": "https://github.com/fermio-technologies/fermio-sec-cli",
                    "rules": sarif_rules,
                }
            },
            "results": results,
        }]
    })
}

fn sarif_result(finding: &Finding, rule_index: usize) -> Value {
    json!({
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": sarif_level(finding.severity),
        "message": { "text": finding.description },
        "partialFingerprints": {
            "fermioFingerprint/v1": finding.fingerprint,
        },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {
                    "uri": finding.location.path.to_string_lossy().replace('\\', "/"),
                    "uriBaseId": "%SRCROOT%",
                },
                "region": {
                    "startLine": finding.location.start_line,
                    "startColumn": finding.location.start_column,
                    "endLine": finding.location.end_line,
                    "endColumn": finding.location.end_column,
                }
            }
        }],
        "properties": {
            "confidence": format!("{:?}", finding.confidence).to_ascii_lowercase(),
            "framework": finding.framework,
        }
    })
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "note",
        Severity::Medium => "warning",
        Severity::High | Severity::Critical => "error",
    }
}

fn display_frameworks(frameworks: &[String]) -> String {
    if frameworks.is_empty() {
        "generic-php".to_string()
    } else {
        frameworks.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fermio_core::{Confidence, Finding, ProjectMetadata, ScanStatistics, SourceLocation};

    fn result() -> ScanResult {
        ScanResult {
            project: ProjectMetadata {
                root: ".".into(),
                languages: vec!["php".to_string()],
                frameworks: Vec::new(),
            },
            statistics: ScanStatistics {
                findings: 1,
                ..ScanStatistics::default()
            },
            diagnostics: Vec::new(),
            findings: vec![Finding {
                rule_id: "FERMIO-PHP-CORE-CMD-001".to_string(),
                title: "Operating system command execution".to_string(),
                description: "The PHP function `system` requires security review.".to_string(),
                severity: Severity::High,
                confidence: Confidence::High,
                location: SourceLocation {
                    path: "src/example.php".into(),
                    start_line: 2,
                    start_column: 1,
                    end_line: 2,
                    end_column: 15,
                },
                fingerprint: "abc123".to_string(),
                cwe: Some("CWE-78".to_string()),
                framework: None,
            }],
        }
    }

    #[test]
    fn writes_sarif_2_1_0_with_fingerprint() {
        let report = sarif_report(&result());
        assert_eq!(report["version"], "2.1.0");
        assert_eq!(
            report["runs"][0]["results"][0]["partialFingerprints"]
                ["fermioFingerprint/v1"],
            "abc123"
        );
        assert_eq!(report["runs"][0]["results"][0]["ruleIndex"], 0);
    }
}

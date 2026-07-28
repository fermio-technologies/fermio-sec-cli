use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashSet},
    path::PathBuf,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceLocation {
    pub path: PathBuf,
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataflowStep {
    pub label: String,
    pub location: SourceLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnostic {
    pub code: String,
    pub message: String,
    pub severity: DiagnosticSeverity,
    pub location: Option<SourceLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub location: SourceLocation,
    pub fingerprint: String,
    pub cwe: Option<String>,
    pub framework: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dataflow: Vec<DataflowStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectMetadata {
    pub root: PathBuf,
    pub languages: Vec<String>,
    pub frameworks: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanStatistics {
    pub files_discovered: usize,
    pub files_parsed: usize,
    pub files_skipped: usize,
    pub parse_errors: usize,
    pub diagnostics: usize,
    pub findings: usize,
    #[serde(default)]
    pub suppressed_findings: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub project: ProjectMetadata,
    pub statistics: ScanStatistics,
    pub diagnostics: Vec<Diagnostic>,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingBaseline {
    pub schema_version: u32,
    pub fingerprints: Vec<String>,
}

impl FindingBaseline {
    pub const SCHEMA_VERSION: u32 = 1;

    pub fn from_result(result: &ScanResult) -> Self {
        let fingerprints = result
            .findings
            .iter()
            .map(|finding| finding.fingerprint.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();

        Self {
            schema_version: Self::SCHEMA_VERSION,
            fingerprints,
        }
    }

    pub fn apply(&self, result: &mut ScanResult) -> usize {
        let known = self
            .fingerprints
            .iter()
            .map(String::as_str)
            .collect::<HashSet<_>>();
        let before = result.findings.len();
        result
            .findings
            .retain(|finding| !known.contains(finding.fingerprint.as_str()));
        let suppressed = before - result.findings.len();
        result.statistics.findings = result.findings.len();
        result.statistics.suppressed_findings += suppressed;
        suppressed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(fingerprint: &str) -> Finding {
        Finding {
            rule_id: "RULE-001".to_string(),
            title: "Example".to_string(),
            description: "Example finding".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            location: SourceLocation {
                path: "src/example.php".into(),
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 10,
            },
            fingerprint: fingerprint.to_string(),
            cwe: None,
            framework: None,
            dataflow: Vec::new(),
        }
    }

    fn result(findings: Vec<Finding>) -> ScanResult {
        ScanResult {
            project: ProjectMetadata {
                root: ".".into(),
                languages: vec!["php".to_string()],
                frameworks: Vec::new(),
            },
            statistics: ScanStatistics {
                findings: findings.len(),
                ..ScanStatistics::default()
            },
            diagnostics: Vec::new(),
            findings,
        }
    }

    #[test]
    fn baseline_deduplicates_and_sorts_fingerprints() {
        let result = result(vec![finding("b"), finding("a"), finding("b")]);
        let baseline = FindingBaseline::from_result(&result);

        assert_eq!(baseline.schema_version, FindingBaseline::SCHEMA_VERSION);
        assert_eq!(baseline.fingerprints, vec!["a", "b"]);
    }

    #[test]
    fn baseline_suppresses_only_known_findings() {
        let baseline = FindingBaseline {
            schema_version: FindingBaseline::SCHEMA_VERSION,
            fingerprints: vec!["known".to_string()],
        };
        let mut result = result(vec![finding("known"), finding("new")]);

        assert_eq!(baseline.apply(&mut result), 1);
        assert_eq!(result.statistics.findings, 1);
        assert_eq!(result.statistics.suppressed_findings, 1);
        assert_eq!(result.findings[0].fingerprint, "new");
    }
}

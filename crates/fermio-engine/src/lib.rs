use anyhow::{bail, Context, Result};
use fermio_core::{Diagnostic, DiagnosticSeverity, ProjectMetadata, ScanResult, ScanStatistics};
use fermio_language_api::{LanguageFrontend, SourceFile};
use fermio_rules::{ModuleAnalysis, Rule};
use ignore::WalkBuilder;
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub include_vendor: bool,
    pub max_files: usize,
    pub max_file_size: u64,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            include_vendor: false,
            max_files: 100_000,
            max_file_size: 2 * 1024 * 1024,
        }
    }
}

pub struct ScanEngine {
    frontends: Vec<Box<dyn LanguageFrontend>>,
    rules: Vec<Box<dyn Rule>>,
}

impl ScanEngine {
    pub fn new(frontends: Vec<Box<dyn LanguageFrontend>>, rules: Vec<Box<dyn Rule>>) -> Self {
        Self { frontends, rules }
    }

    pub fn scan(&self, root: &Path, include_vendor: bool) -> Result<ScanResult> {
        self.scan_with_options(
            root,
            ScanOptions {
                include_vendor,
                ..ScanOptions::default()
            },
        )
    }

    pub fn scan_with_options(&self, root: &Path, options: ScanOptions) -> Result<ScanResult> {
        let root = root
            .canonicalize()
            .with_context(|| format!("cannot access {}", root.display()))?;

        let frontend = self
            .frontends
            .iter()
            .find(|frontend| frontend.id() == "php")
            .context("PHP frontend is not registered")?;
        let detection = frontend.detect_project(&root)?;
        let files = discover_files(&root, &options)?;
        let mut statistics = ScanStatistics {
            files_discovered: files.len(),
            ..ScanStatistics::default()
        };
        let mut findings = Vec::new();
        let mut diagnostics = Vec::new();

        for path in files {
            if !frontend.supports_file(&path) {
                continue;
            }

            let relative = path.strip_prefix(&root).unwrap_or(&path).to_path_buf();
            let metadata = match fs::metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) => {
                    statistics.files_skipped += 1;
                    diagnostics.push(Diagnostic {
                        code: "SCAN-READ-001".to_string(),
                        message: format!("Failed to inspect file: {error}"),
                        severity: DiagnosticSeverity::Warning,
                        location: None,
                    });
                    continue;
                }
            };

            if metadata.len() > options.max_file_size {
                statistics.files_skipped += 1;
                diagnostics.push(Diagnostic {
                    code: "SCAN-LIMIT-001".to_string(),
                    message: format!(
                        "Skipped {} because it exceeds the {} byte file-size limit",
                        relative.display(),
                        options.max_file_size
                    ),
                    severity: DiagnosticSeverity::Warning,
                    location: None,
                });
                continue;
            }

            let content = match fs::read_to_string(&path) {
                Ok(content) => content,
                Err(error) => {
                    statistics.files_skipped += 1;
                    diagnostics.push(Diagnostic {
                        code: "SCAN-READ-002".to_string(),
                        message: format!("Failed to read {}: {error}", relative.display()),
                        severity: DiagnosticSeverity::Warning,
                        location: None,
                    });
                    continue;
                }
            };
            let source = SourceFile {
                path: relative,
                content,
            };

            match frontend.parse_and_lower(&source) {
                Ok(output) => {
                    statistics.files_parsed += 1;
                    statistics.parse_errors += output
                        .diagnostics
                        .iter()
                        .filter(|diagnostic| diagnostic.code == "PHP-PARSE-001")
                        .count();
                    diagnostics.extend(output.diagnostics);

                    let analysis = ModuleAnalysis::new(&output.module);
                    for rule in &self.rules {
                        findings.extend(rule.evaluate(&analysis));
                    }
                }
                Err(error) => {
                    statistics.parse_errors += 1;
                    diagnostics.push(Diagnostic {
                        code: "PHP-PARSE-002".to_string(),
                        message: error.to_string(),
                        severity: DiagnosticSeverity::Error,
                        location: None,
                    });
                }
            }
        }

        findings.sort_by(|left, right| {
            right
                .severity
                .cmp(&left.severity)
                .then_with(|| left.location.path.cmp(&right.location.path))
                .then_with(|| left.location.start_line.cmp(&right.location.start_line))
        });
        diagnostics.sort_by(|left, right| left.code.cmp(&right.code));
        statistics.findings = findings.len();
        statistics.diagnostics = diagnostics.len();

        Ok(ScanResult {
            project: ProjectMetadata {
                root,
                languages: vec![detection.language],
                frameworks: detection.frameworks,
            },
            statistics,
            diagnostics,
            findings,
        })
    }
}

fn discover_files(root: &Path, options: &ScanOptions) -> Result<Vec<PathBuf>> {
    let mut builder = WalkBuilder::new(root);
    builder
        .hidden(false)
        .follow_links(false)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .add_custom_ignore_filename(".fermioignore");

    let mut files = builder
        .build()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_some_and(|kind| kind.is_file()))
        .map(|entry| entry.into_path())
        .filter(|path| {
            options.include_vendor || !path.components().any(|part| part.as_os_str() == "vendor")
        })
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("php"))
        .collect::<Vec<_>>();

    files.sort();
    if files.len() > options.max_files {
        bail!(
            "scan discovered {} PHP files, exceeding the configured limit of {}",
            files.len(),
            options.max_files
        );
    }

    Ok(files)
}

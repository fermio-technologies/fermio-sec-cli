use anyhow::{Context, Result};
use fermio_core::{ProjectMetadata, ScanResult, ScanStatistics};
use fermio_language_api::{LanguageFrontend, SourceFile};
use fermio_rules::Rule;
use ignore::WalkBuilder;
use std::{
    fs,
    path::{Path, PathBuf},
};

pub struct ScanEngine {
    frontends: Vec<Box<dyn LanguageFrontend>>,
    rules: Vec<Box<dyn Rule>>,
}

impl ScanEngine {
    pub fn new(frontends: Vec<Box<dyn LanguageFrontend>>, rules: Vec<Box<dyn Rule>>) -> Self {
        Self { frontends, rules }
    }

    pub fn scan(&self, root: &Path, include_vendor: bool) -> Result<ScanResult> {
        let root = root
            .canonicalize()
            .with_context(|| format!("cannot access {}", root.display()))?;

        let frontend = self
            .frontends
            .iter()
            .find(|frontend| frontend.id() == "php")
            .context("PHP frontend is not registered")?;
        let detection = frontend.detect_project(&root)?;
        let files = discover_files(&root, include_vendor)?;
        let mut statistics = ScanStatistics {
            files_discovered: files.len(),
            ..ScanStatistics::default()
        };
        let mut findings = Vec::new();

        for path in files {
            if !frontend.supports_file(&path) {
                continue;
            }

            let content = fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            let relative = path.strip_prefix(&root).unwrap_or(&path).to_path_buf();
            let source = SourceFile {
                path: relative,
                content,
            };

            match frontend.parse_and_lower(&source) {
                Ok(module) => {
                    statistics.files_parsed += 1;
                    for rule in &self.rules {
                        findings.extend(rule.evaluate(&module));
                    }
                }
                Err(_) => statistics.parse_errors += 1,
            }
        }

        findings.sort_by(|left, right| {
            right
                .severity
                .cmp(&left.severity)
                .then_with(|| left.location.path.cmp(&right.location.path))
                .then_with(|| left.location.start_line.cmp(&right.location.start_line))
        });
        statistics.findings = findings.len();

        Ok(ScanResult {
            project: ProjectMetadata {
                root,
                languages: vec![detection.language],
                frameworks: detection.frameworks,
            },
            statistics,
            findings,
        })
    }
}

fn discover_files(root: &Path, include_vendor: bool) -> Result<Vec<PathBuf>> {
    let mut builder = WalkBuilder::new(root);
    builder
        .hidden(false)
        .follow_links(false)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true);

    let files = builder
        .build()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_some_and(|kind| kind.is_file()))
        .map(|entry| entry.into_path())
        .filter(|path| {
            include_vendor || !path.components().any(|part| part.as_os_str() == "vendor")
        })
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("php"))
        .collect();

    Ok(files)
}

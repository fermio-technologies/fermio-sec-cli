use anyhow::Result;
use fermio_ir::ModuleIr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct SourceFile {
    pub path: PathBuf,
    pub content: String,
}

#[derive(Debug, Clone, Default)]
pub struct ProjectDetection {
    pub language: String,
    pub frameworks: Vec<String>,
    pub confidence: u8,
}

pub trait LanguageFrontend: Send + Sync {
    fn id(&self) -> &'static str;
    fn supports_file(&self, path: &Path) -> bool;
    fn detect_project(&self, root: &Path) -> Result<ProjectDetection>;
    fn parse_and_lower(&self, file: &SourceFile) -> Result<ModuleIr>;
}

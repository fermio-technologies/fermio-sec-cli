use anyhow::{Context, Result};
use fermio_core::SourceLocation;
use fermio_ir::{Instruction, ModuleIr};
use fermio_language_api::{LanguageFrontend, ProjectDetection, SourceFile};
use serde_json::Value;
use std::{fs, path::Path};
use tree_sitter::{Node, Parser};

#[derive(Debug, Default)]
pub struct PhpFrontend;

impl PhpFrontend {
    pub fn new() -> Self {
        Self
    }
}

impl LanguageFrontend for PhpFrontend {
    fn id(&self) -> &'static str {
        "php"
    }

    fn supports_file(&self, path: &Path) -> bool {
        path.extension().and_then(|value| value.to_str()) == Some("php")
    }

    fn detect_project(&self, root: &Path) -> Result<ProjectDetection> {
        let mut frameworks = Vec::new();
        let composer = root.join("composer.json");

        if composer.is_file() {
            let content = fs::read_to_string(&composer)
                .with_context(|| format!("failed to read {}", composer.display()))?;
            let manifest: Value = serde_json::from_str(&content)
                .with_context(|| format!("invalid JSON in {}", composer.display()))?;
            let packages = manifest
                .get("require")
                .and_then(Value::as_object)
                .into_iter()
                .flatten()
                .chain(
                    manifest
                        .get("require-dev")
                        .and_then(Value::as_object)
                        .into_iter()
                        .flatten(),
                )
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>();

            if packages.contains(&"laravel/framework") {
                frameworks.push("laravel".to_string());
            }
            if packages.contains(&"symfony/framework-bundle") {
                frameworks.push("symfony".to_string());
            }
        }

        if root.join("wp-includes/version.php").is_file()
            || root.join("wp-config.php").is_file()
            || root.join("wp-content").is_dir()
        {
            frameworks.push("wordpress".to_string());
        }

        frameworks.sort();
        frameworks.dedup();

        Ok(ProjectDetection {
            language: "php".to_string(),
            confidence: if composer.is_file() { 100 } else { 80 },
            frameworks,
        })
    }

    fn parse_and_lower(&self, file: &SourceFile) -> Result<ModuleIr> {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
            .context("failed to initialize PHP grammar")?;

        let tree = parser
            .parse(&file.content, None)
            .context("Tree-sitter did not return a PHP syntax tree")?;

        let mut instructions = Vec::new();
        collect_calls(
            tree.root_node(),
            file.content.as_bytes(),
            &file.path,
            &mut instructions,
        );

        Ok(ModuleIr {
            language: "php".to_string(),
            path: file.path.to_string_lossy().into_owned(),
            instructions,
        })
    }
}

fn collect_calls(node: Node<'_>, source: &[u8], path: &Path, output: &mut Vec<Instruction>) {
    if matches!(
        node.kind(),
        "function_call_expression" | "member_call_expression" | "scoped_call_expression"
    ) {
        if let Some(name) = call_name(node, source) {
            let start = node.start_position();
            let end = node.end_position();
            output.push(Instruction::Call {
                target: name,
                arguments: Vec::new(),
                location: SourceLocation {
                    path: path.to_path_buf(),
                    start_line: start.row + 1,
                    start_column: start.column + 1,
                    end_line: end.row + 1,
                    end_column: end.column + 1,
                },
            });
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_calls(child, source, path, output);
    }
}

fn call_name(node: Node<'_>, source: &[u8]) -> Option<String> {
    for field in ["function", "name"] {
        if let Some(candidate) = node.child_by_field_name(field) {
            if let Ok(text) = candidate.utf8_text(source) {
                return Some(text.trim().to_string());
            }
        }
    }
    None
}

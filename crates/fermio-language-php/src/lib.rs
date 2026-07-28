use anyhow::{Context, Result};
use fermio_core::{Diagnostic, DiagnosticSeverity, SourceLocation};
use fermio_ir::{CallKind, Instruction, LiteralValue, ModuleIr, ValueId};
use fermio_language_api::{FrontendOutput, LanguageFrontend, ProjectDetection, SourceFile};
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

    fn parse_and_lower(&self, file: &SourceFile) -> Result<FrontendOutput> {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
            .context("failed to initialize PHP grammar")?;

        let tree = parser
            .parse(&file.content, None)
            .context("Tree-sitter did not return a PHP syntax tree")?;

        let mut diagnostics = Vec::new();
        collect_syntax_diagnostics(tree.root_node(), &file.path, &mut diagnostics);

        let mut lowerer = PhpLowerer::new(file.content.as_bytes(), &file.path);
        lowerer.lower_node(tree.root_node());

        Ok(FrontendOutput {
            module: ModuleIr {
                language: "php".to_string(),
                path: file.path.to_string_lossy().into_owned(),
                instructions: lowerer.instructions,
            },
            diagnostics,
        })
    }
}

struct PhpLowerer<'a> {
    source: &'a [u8],
    path: &'a Path,
    next_value: u32,
    instructions: Vec<Instruction>,
}

impl<'a> PhpLowerer<'a> {
    fn new(source: &'a [u8], path: &'a Path) -> Self {
        Self {
            source,
            path,
            next_value: 0,
            instructions: Vec::new(),
        }
    }

    fn lower_node(&mut self, node: Node<'_>) {
        match node.kind() {
            "assignment_expression" | "reference_assignment_expression" => {
                self.lower_assignment(node);
                return;
            }
            "return_statement" => {
                let value = first_named_child(node).map(|child| self.lower_expression(child));
                self.instructions.push(Instruction::Return {
                    value,
                    location: source_location(node, self.path),
                });
                return;
            }
            "expression_statement" => {
                if let Some(expression) = first_named_child(node) {
                    self.lower_expression(expression);
                }
                return;
            }
            _ => {}
        }

        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            self.lower_node(child);
        }
    }

    fn lower_assignment(&mut self, node: Node<'_>) -> ValueId {
        let right = node
            .child_by_field_name("right")
            .map(|child| self.lower_expression(child))
            .unwrap_or_else(|| self.lower_opaque(node));
        let target = node
            .child_by_field_name("left")
            .and_then(|child| node_text(child, self.source))
            .unwrap_or_else(|| "<unknown>".to_string());

        self.instructions.push(Instruction::Assignment {
            target,
            value: right,
            location: source_location(node, self.path),
        });
        right
    }

    fn lower_expression(&mut self, node: Node<'_>) -> ValueId {
        match node.kind() {
            "variable_name" | "dynamic_variable_name" => {
                let output = self.next_value();
                self.instructions.push(Instruction::VariableRead {
                    output,
                    name: node_text(node, self.source).unwrap_or_else(|| "<unknown>".to_string()),
                    location: source_location(node, self.path),
                });
                output
            }
            "string" | "encapsed_string" | "heredoc" | "nowdoc" => self.lower_literal(
                node,
                LiteralValue::String(node_text(node, self.source).unwrap_or_default()),
            ),
            "integer" => self.lower_literal(
                node,
                LiteralValue::Integer(node_text(node, self.source).unwrap_or_default()),
            ),
            "float" => self.lower_literal(
                node,
                LiteralValue::Float(node_text(node, self.source).unwrap_or_default()),
            ),
            "boolean" => self.lower_literal(
                node,
                LiteralValue::Boolean(
                    node_text(node, self.source)
                        .is_some_and(|value| value.eq_ignore_ascii_case("true")),
                ),
            ),
            "null" => self.lower_literal(node, LiteralValue::Null),
            "assignment_expression" | "reference_assignment_expression" => {
                self.lower_assignment(node)
            }
            "binary_expression" if operator_text(node, self.source).as_deref() == Some(".") => {
                self.lower_concatenation(node)
            }
            "subscript_expression" => self.lower_index_read(node),
            "function_call_expression"
            | "member_call_expression"
            | "nullsafe_member_call_expression"
            | "scoped_call_expression" => self.lower_call(node),
            "parenthesized_expression" | "argument" => first_named_child(node)
                .map(|child| self.lower_expression(child))
                .unwrap_or_else(|| self.lower_opaque(node)),
            _ => self.lower_opaque(node),
        }
    }

    fn lower_literal(&mut self, node: Node<'_>, value: LiteralValue) -> ValueId {
        let output = self.next_value();
        self.instructions.push(Instruction::Literal {
            output,
            value,
            location: source_location(node, self.path),
        });
        output
    }

    fn lower_concatenation(&mut self, node: Node<'_>) -> ValueId {
        let mut operands = Vec::new();
        if let Some(left) = node.child_by_field_name("left") {
            operands.push(self.lower_expression(left));
        }
        if let Some(right) = node.child_by_field_name("right") {
            operands.push(self.lower_expression(right));
        }

        let output = self.next_value();
        self.instructions.push(Instruction::Concatenate {
            output,
            operands,
            location: source_location(node, self.path),
        });
        output
    }

    fn lower_index_read(&mut self, node: Node<'_>) -> ValueId {
        let collection = node
            .named_child(0)
            .map(|child| self.lower_expression(child))
            .unwrap_or_else(|| self.lower_opaque(node));
        let index = node
            .named_child(1)
            .map(|child| self.lower_expression(child));
        let output = self.next_value();
        self.instructions.push(Instruction::IndexRead {
            output,
            collection,
            index,
            location: source_location(node, self.path),
        });
        output
    }

    fn lower_call(&mut self, node: Node<'_>) -> ValueId {
        let (target, call_kind) = call_target(node, self.source);
        let arguments = node
            .child_by_field_name("arguments")
            .map(|arguments| {
                let mut values = Vec::new();
                let mut cursor = arguments.walk();
                for argument in arguments.named_children(&mut cursor) {
                    if argument.kind() == "argument" {
                        if let Some(value_node) = last_named_child(argument) {
                            values.push(self.lower_expression(value_node));
                        }
                    }
                }
                values
            })
            .unwrap_or_default();

        let output = self.next_value();
        self.instructions.push(Instruction::Call {
            output,
            target,
            call_kind,
            arguments,
            location: source_location(node, self.path),
        });
        output
    }

    fn lower_opaque(&mut self, node: Node<'_>) -> ValueId {
        let output = self.next_value();
        self.instructions.push(Instruction::Opaque {
            output,
            expression: node_text(node, self.source).unwrap_or_default(),
            location: source_location(node, self.path),
        });
        output
    }

    fn next_value(&mut self) -> ValueId {
        let value = ValueId(self.next_value);
        self.next_value += 1;
        value
    }
}

fn call_target(node: Node<'_>, source: &[u8]) -> (String, CallKind) {
    match node.kind() {
        "function_call_expression" => {
            let function = node.child_by_field_name("function");
            let target = function
                .and_then(|child| node_text(child, source))
                .unwrap_or_else(|| "<dynamic>".to_string());
            let kind = if function.is_some_and(|child| {
                matches!(child.kind(), "name" | "qualified_name" | "relative_name")
            }) {
                CallKind::Function
            } else {
                CallKind::Dynamic
            };
            (target, kind)
        }
        "member_call_expression" => (
            node.child_by_field_name("name")
                .and_then(|child| node_text(child, source))
                .unwrap_or_else(|| "<dynamic>".to_string()),
            CallKind::Method,
        ),
        "nullsafe_member_call_expression" => (
            node.child_by_field_name("name")
                .and_then(|child| node_text(child, source))
                .unwrap_or_else(|| "<dynamic>".to_string()),
            CallKind::NullsafeMethod,
        ),
        "scoped_call_expression" => (
            node.child_by_field_name("name")
                .and_then(|child| node_text(child, source))
                .unwrap_or_else(|| "<dynamic>".to_string()),
            CallKind::StaticMethod,
        ),
        _ => ("<dynamic>".to_string(), CallKind::Dynamic),
    }
}

fn operator_text(node: Node<'_>, source: &[u8]) -> Option<String> {
    node.child_by_field_name("operator")
        .and_then(|operator| node_text(operator, source))
}

fn first_named_child(node: Node<'_>) -> Option<Node<'_>> {
    node.named_child(0)
}

fn last_named_child(node: Node<'_>) -> Option<Node<'_>> {
    node.named_child_count()
        .checked_sub(1)
        .and_then(|index| node.named_child(index))
}

fn node_text(node: Node<'_>, source: &[u8]) -> Option<String> {
    node.utf8_text(source)
        .ok()
        .map(|text| text.trim().to_string())
}

fn collect_syntax_diagnostics(node: Node<'_>, path: &Path, diagnostics: &mut Vec<Diagnostic>) {
    if node.is_error() || node.is_missing() {
        diagnostics.push(Diagnostic {
            code: "PHP-PARSE-001".to_string(),
            message: if node.is_missing() {
                format!("Missing PHP syntax element: {}", node.kind())
            } else {
                "Unexpected or incomplete PHP syntax".to_string()
            },
            severity: DiagnosticSeverity::Error,
            location: Some(source_location(node, path)),
        });
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_syntax_diagnostics(child, path, diagnostics);
    }
}

fn source_location(node: Node<'_>, path: &Path) -> SourceLocation {
    let start = node.start_position();
    let end = node.end_position();
    SourceLocation {
        path: path.to_path_buf(),
        start_line: start.row + 1,
        start_column: start.column + 1,
        end_line: end.row + 1,
        end_column: end.column + 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lower(source: &str) -> FrontendOutput {
        PhpFrontend::new()
            .parse_and_lower(&SourceFile {
                path: "example.php".into(),
                content: source.to_string(),
            })
            .expect("frontend should lower PHP")
    }

    #[test]
    fn reports_invalid_php_as_diagnostic() {
        let output = lower("<?php function broken( {");
        assert!(!output.diagnostics.is_empty());
        assert_eq!(output.diagnostics[0].code, "PHP-PARSE-001");
    }

    #[test]
    fn lowers_assignment_concatenation_and_call_arguments() {
        let output = lower("<?php $command = 'ls ' . $input; system($command);");

        assert!(output
            .module
            .instructions
            .iter()
            .any(|instruction| matches!(instruction, Instruction::Assignment { target, .. } if target == "$command")));
        assert!(output
            .module
            .instructions
            .iter()
            .any(|instruction| matches!(instruction, Instruction::Concatenate { operands, .. } if operands.len() == 2)));
        assert!(output.module.instructions.iter().any(|instruction| {
            matches!(instruction, Instruction::Call { target, arguments, .. } if target == "system" && arguments.len() == 1)
        }));
    }

    #[test]
    fn lowers_superglobal_index_reads() {
        let output = lower("<?php system($_GET['cmd']);");

        assert!(output.module.instructions.iter().any(|instruction| {
            matches!(instruction, Instruction::VariableRead { name, .. } if name == "$_GET")
        }));
        assert!(output.module.instructions.iter().any(|instruction| {
            matches!(instruction, Instruction::IndexRead { index: Some(_), .. })
        }));
    }

    #[test]
    fn lowers_return_values() {
        let output = lower("<?php function value() { return $input; }");
        assert!(output
            .module
            .instructions
            .iter()
            .any(|instruction| matches!(instruction, Instruction::Return { value: Some(_), .. })));
    }
}

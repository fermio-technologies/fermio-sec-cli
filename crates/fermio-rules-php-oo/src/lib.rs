use fermio_core::{Confidence, DataflowStep, Finding, Severity, SourceLocation};
use fermio_ir::{CallKind, Instruction, ModuleIr, ValueId};
use fermio_rules::{ModuleAnalysis, Rule};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

const RULE_ID: &str = "FERMIO-PHP-TAINT-SQL-OO-001";

pub fn built_in_rules() -> Vec<Box<dyn Rule>> {
    vec![Box::new(ObjectSqlTaintRule)]
}

pub struct ObjectSqlTaintRule;

#[derive(Debug, Clone)]
struct SqlTaintFact {
    source: String,
    steps: Vec<DataflowStep>,
    sanitized: bool,
}

impl SqlTaintFact {
    fn source(source: String, location: &SourceLocation) -> Self {
        Self {
            source: source.clone(),
            steps: vec![DataflowStep {
                label: format!("Untrusted input from `{source}`"),
                location: location.clone(),
            }],
            sanitized: false,
        }
    }

    fn propagated(&self, label: impl Into<String>, location: &SourceLocation) -> Self {
        let mut fact = self.clone();
        fact.steps.push(DataflowStep {
            label: label.into(),
            location: location.clone(),
        });
        fact
    }

    fn sql_sanitized(&self, label: impl Into<String>, location: &SourceLocation) -> Self {
        let mut fact = self.propagated(label, location);
        fact.sanitized = true;
        fact
    }

    fn merge_for_concatenation(
        facts: Vec<Self>,
        location: &SourceLocation,
    ) -> Option<Self> {
        let sanitized = facts.iter().all(|fact| fact.sanitized);
        let mut merged = facts.into_iter().next()?;
        merged.sanitized = sanitized;
        Some(merged.propagated("String concatenation", location))
    }
}

#[derive(Default)]
struct AnalysisState {
    variables: HashMap<String, SqlTaintFact>,
    taint: HashMap<ValueId, SqlTaintFact>,
}

impl Rule for ObjectSqlTaintRule {
    fn id(&self) -> &'static str {
        RULE_ID
    }

    fn evaluate(&self, analysis: &ModuleAnalysis<'_>) -> Vec<Finding> {
        analyze_module(analysis.module())
    }
}

fn analyze_module(module: &ModuleIr) -> Vec<Finding> {
    let mut state = AnalysisState::default();
    let mut variable_scopes = Vec::<HashMap<String, SqlTaintFact>>::new();
    let mut findings = Vec::new();

    for instruction in &module.instructions {
        match instruction {
            Instruction::FunctionStart { .. } => {
                variable_scopes.push(std::mem::take(&mut state.variables));
            }
            Instruction::FunctionEnd { .. } => {
                state.variables = variable_scopes.pop().unwrap_or_default();
            }
            Instruction::VariableRead {
                output,
                name,
                location,
            } => {
                if is_untrusted_superglobal(name) {
                    state
                        .taint
                        .insert(*output, SqlTaintFact::source(name.clone(), location));
                } else if let Some(fact) = state.variables.get(name) {
                    state.taint.insert(
                        *output,
                        fact.propagated(format!("Read from `{name}`"), location),
                    );
                }
            }
            Instruction::Assignment {
                target,
                value,
                location,
            } => {
                if let Some(fact) = state.taint.get(value).cloned() {
                    state.variables.insert(
                        target.clone(),
                        fact.propagated(format!("Assigned to `{target}`"), location),
                    );
                } else {
                    state.variables.remove(target);
                }
            }
            Instruction::Concatenate {
                output,
                operands,
                location,
            } => {
                let facts = operands
                    .iter()
                    .filter_map(|value| state.taint.get(value).cloned())
                    .collect::<Vec<_>>();
                if let Some(fact) = SqlTaintFact::merge_for_concatenation(facts, location) {
                    state.taint.insert(*output, fact);
                }
            }
            Instruction::IndexRead {
                output,
                collection,
                location,
                ..
            } => {
                if let Some(fact) = state.taint.get(collection) {
                    state
                        .taint
                        .insert(*output, fact.propagated("Indexed value read", location));
                }
            }
            Instruction::Call {
                output,
                target,
                call_kind,
                arguments,
                location,
            } => {
                if let Some(argument) = sql_sanitizer_argument(target, *call_kind, arguments) {
                    if let Some(fact) = state.taint.get(&argument) {
                        state.taint.insert(
                            *output,
                            fact.sql_sanitized(
                                format!("Sanitized for SQL use by `{}`", display_target(target)),
                                location,
                            ),
                        );
                    }
                    continue;
                }

                if let Some(argument) = cross_domain_passthrough_argument(
                    target,
                    *call_kind,
                    arguments,
                ) {
                    if let Some(fact) = state.taint.get(&argument) {
                        state.taint.insert(
                            *output,
                            fact.propagated(
                                format!("Passed through `{}`", display_target(target)),
                                location,
                            ),
                        );
                    }
                }

                if let Some((sink, argument)) = object_sql_sink(target, *call_kind, arguments) {
                    let Some(fact) = state.taint.get(&argument) else {
                        continue;
                    };
                    if fact.sanitized {
                        continue;
                    }

                    let mut dataflow = fact.steps.clone();
                    dataflow.push(DataflowStep {
                        label: format!("Object SQL query sink `{sink}`"),
                        location: location.clone(),
                    });
                    findings.push(Finding {
                        rule_id: RULE_ID.to_string(),
                        title: "User-controlled object SQL query".to_string(),
                        description: format!(
                            "Data originating from `{}` reaches `{sink}` without recognized SQL sanitization or a fixed query boundary.",
                            fact.source
                        ),
                        severity: Severity::Critical,
                        confidence: Confidence::High,
                        location: location.clone(),
                        fingerprint: fingerprint(
                            RULE_ID,
                            &format!("{sink}:{}", fact.source),
                            location,
                        ),
                        cwe: Some("CWE-89".to_string()),
                        framework: None,
                        dataflow,
                    });
                }
            }
            _ => {}
        }
    }

    findings
}

fn object_sql_sink(
    target: &str,
    call_kind: CallKind,
    arguments: &[ValueId],
) -> Option<(&'static str, ValueId)> {
    if !matches!(call_kind, CallKind::Method | CallKind::NullsafeMethod) {
        return None;
    }

    let sink = match normalized_target(target).as_str() {
        "pdo::exec" => "PDO::exec",
        "pdo::prepare" => "PDO::prepare",
        "pdo::query" => "PDO::query",
        "mysqli::execute_query" => "mysqli::execute_query",
        "mysqli::multi_query" => "mysqli::multi_query",
        "mysqli::prepare" => "mysqli::prepare",
        "mysqli::query" => "mysqli::query",
        "mysqli::real_query" => "mysqli::real_query",
        _ => return None,
    };

    arguments.first().copied().map(|argument| (sink, argument))
}

fn sql_sanitizer_argument(
    target: &str,
    call_kind: CallKind,
    arguments: &[ValueId],
) -> Option<ValueId> {
    let normalized = normalized_target(target);
    match call_kind {
        CallKind::Method | CallKind::NullsafeMethod => match normalized.as_str() {
            "pdo::quote" | "mysqli::escape_string" | "mysqli::real_escape_string" => {
                arguments.first().copied()
            }
            _ => None,
        },
        CallKind::Function => match normalized.as_str() {
            "mysql_real_escape_string" => arguments.first().copied(),
            "mysqli_escape_string" | "mysqli_real_escape_string" => {
                arguments.get(1).copied()
            }
            "pg_escape_identifier" | "pg_escape_literal" | "pg_escape_string" => {
                arguments.last().copied()
            }
            _ => None,
        },
        _ => None,
    }
}

fn cross_domain_passthrough_argument(
    target: &str,
    call_kind: CallKind,
    arguments: &[ValueId],
) -> Option<ValueId> {
    if call_kind != CallKind::Function {
        return None;
    }

    match normalized_target(target).as_str() {
        "escapeshellarg" | "escapeshellcmd" | "htmlentities" | "htmlspecialchars" => {
            arguments.first().copied()
        }
        _ => None,
    }
}

fn normalized_target(target: &str) -> String {
    target
        .trim()
        .trim_start_matches('\\')
        .to_ascii_lowercase()
}

fn display_target(target: &str) -> &str {
    target.trim().trim_start_matches('\\')
}

fn is_untrusted_superglobal(name: &str) -> bool {
    matches!(
        name,
        "$_COOKIE" | "$_FILES" | "$_GET" | "$_POST" | "$_REQUEST" | "$_SERVER"
    )
}

fn fingerprint(rule_id: &str, semantic_anchor: &str, location: &SourceLocation) -> String {
    let normalized_path = location.path.to_string_lossy().replace('\\', "/");
    let mut hasher = Sha256::new();
    hasher.update(rule_id.as_bytes());
    hasher.update([0]);
    hasher.update(normalized_path.as_bytes());
    hasher.update([0]);
    hasher.update(semantic_anchor.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn location(line: usize) -> SourceLocation {
        SourceLocation {
            path: "src/example.php".into(),
            start_line: line,
            start_column: 1,
            end_line: line,
            end_column: 20,
        }
    }

    fn call(
        output: u32,
        target: &str,
        call_kind: CallKind,
        arguments: Vec<ValueId>,
        line: usize,
    ) -> Instruction {
        Instruction::Call {
            output: ValueId(output),
            target: target.to_string(),
            call_kind,
            arguments,
            location: location(line),
        }
    }

    fn tainted_input(source: &str) -> Vec<Instruction> {
        vec![
            Instruction::VariableRead {
                output: ValueId(0),
                name: source.to_string(),
                location: location(1),
            },
            Instruction::IndexRead {
                output: ValueId(1),
                collection: ValueId(0),
                index: None,
                location: location(1),
            },
        ]
    }

    fn module(instructions: Vec<Instruction>) -> ModuleIr {
        ModuleIr {
            language: "php".to_string(),
            path: "src/example.php".to_string(),
            instructions,
        }
    }

    fn findings(instructions: Vec<Instruction>) -> Vec<Finding> {
        analyze_module(&module(instructions))
    }

    #[test]
    fn reports_tainted_pdo_query() {
        let mut instructions = tainted_input("$_GET");
        instructions.push(call(
            2,
            "PDO::query",
            CallKind::Method,
            vec![ValueId(1)],
            2,
        ));
        let findings = findings(instructions);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].cwe.as_deref(), Some("CWE-89"));
        assert!(findings[0]
            .dataflow
            .iter()
            .any(|step| step.label.contains("PDO::query")));
    }

    #[test]
    fn reports_tainted_mysqli_prepare_query_text() {
        let mut instructions = tainted_input("$_POST");
        instructions.push(call(
            2,
            "mysqli::prepare",
            CallKind::Method,
            vec![ValueId(1)],
            2,
        ));
        assert_eq!(findings(instructions).len(), 1);
    }

    #[test]
    fn pdo_quote_suppresses_object_sql_finding() {
        let mut instructions = tainted_input("$_REQUEST");
        instructions.push(call(
            2,
            "PDO::quote",
            CallKind::Method,
            vec![ValueId(1)],
            2,
        ));
        instructions.push(call(
            3,
            "PDO::query",
            CallKind::Method,
            vec![ValueId(2)],
            3,
        ));
        assert!(findings(instructions).is_empty());
    }

    #[test]
    fn procedural_sql_sanitizer_suppresses_object_sink() {
        let mut instructions = tainted_input("$_GET");
        instructions.push(call(
            2,
            "mysql_real_escape_string",
            CallKind::Function,
            vec![ValueId(1)],
            2,
        ));
        instructions.push(call(
            3,
            "mysqli::query",
            CallKind::Method,
            vec![ValueId(2)],
            3,
        ));
        assert!(findings(instructions).is_empty());
    }

    #[test]
    fn shell_sanitizer_does_not_hide_object_sql_taint() {
        let mut instructions = tainted_input("$_GET");
        instructions.push(call(
            2,
            "escapeshellarg",
            CallKind::Function,
            vec![ValueId(1)],
            2,
        ));
        instructions.push(call(
            3,
            "PDO::exec",
            CallKind::Method,
            vec![ValueId(2)],
            3,
        ));
        assert_eq!(findings(instructions).len(), 1);
    }

    #[test]
    fn ignores_untyped_query_method() {
        let mut instructions = tainted_input("$_GET");
        instructions.push(call(
            2,
            "query",
            CallKind::Method,
            vec![ValueId(1)],
            2,
        ));
        assert!(findings(instructions).is_empty());
    }

    #[test]
    fn ignores_constant_object_query() {
        let instructions = vec![
            Instruction::Literal {
                output: ValueId(0),
                value: fermio_ir::LiteralValue::String("'SELECT 1'".to_string()),
                location: location(1),
            },
            call(
                1,
                "PDO::query",
                CallKind::Method,
                vec![ValueId(0)],
                1,
            ),
        ];
        assert!(findings(instructions).is_empty());
    }
}

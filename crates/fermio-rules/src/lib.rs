use fermio_core::{Confidence, Finding, Severity, SourceLocation};
use fermio_ir::{CallKind, Instruction, LiteralValue, ModuleIr, ValueId};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

const COMMAND_FUNCTIONS: &[&str] = &[
    "exec",
    "passthru",
    "popen",
    "proc_open",
    "shell_exec",
    "system",
];

pub trait Rule: Send + Sync {
    fn id(&self) -> &'static str;
    fn evaluate(&self, analysis: &ModuleAnalysis<'_>) -> Vec<Finding>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintFact {
    pub source: String,
}

pub struct ModuleAnalysis<'a> {
    module: &'a ModuleIr,
    producers: HashMap<ValueId, &'a Instruction>,
    aliases: HashMap<ValueId, ValueId>,
    taint: HashMap<ValueId, TaintFact>,
}

impl<'a> ModuleAnalysis<'a> {
    pub fn new(module: &'a ModuleIr) -> Self {
        let mut producers = HashMap::new();
        let mut aliases = HashMap::new();
        let mut taint = HashMap::new();
        let mut assignments = HashMap::<String, ValueId>::new();

        for instruction in &module.instructions {
            if let Some(output) = instruction_output(instruction) {
                producers.insert(output, instruction);
            }

            match instruction {
                Instruction::VariableRead { output, name, .. } => {
                    if is_untrusted_superglobal(name) {
                        taint.insert(
                            *output,
                            TaintFact {
                                source: name.clone(),
                            },
                        );
                    } else if let Some(value) = assignments.get(name) {
                        aliases.insert(*output, *value);
                        if let Some(fact) = taint.get(value).cloned() {
                            taint.insert(*output, fact);
                        }
                    }
                }
                Instruction::Assignment { target, value, .. } => {
                    assignments.insert(target.clone(), *value);
                }
                Instruction::Concatenate {
                    output, operands, ..
                } => {
                    if let Some(fact) = operands.iter().find_map(|value| taint.get(value)).cloned() {
                        taint.insert(*output, fact);
                    }
                }
                Instruction::IndexRead {
                    output, collection, ..
                } => {
                    if let Some(fact) = taint.get(collection).cloned() {
                        taint.insert(*output, fact);
                    }
                }
                _ => {}
            }
        }

        Self {
            module,
            producers,
            aliases,
            taint,
        }
    }

    pub fn module(&self) -> &'a ModuleIr {
        self.module
    }

    pub fn taint(&self, value: ValueId) -> Option<&TaintFact> {
        self.taint.get(&value)
    }

    pub fn resolve_constant_string(&self, value: ValueId) -> Option<String> {
        self.resolve_constant_string_inner(value, &mut HashSet::new(), 0)
    }

    fn resolve_constant_string_inner(
        &self,
        value: ValueId,
        visited: &mut HashSet<ValueId>,
        depth: usize,
    ) -> Option<String> {
        if depth > 32 || !visited.insert(value) {
            return None;
        }

        if let Some(alias) = self.aliases.get(&value) {
            return self.resolve_constant_string_inner(*alias, visited, depth + 1);
        }

        match self.producers.get(&value).copied()? {
            Instruction::Literal {
                value: LiteralValue::String(value),
                ..
            } => normalize_string_literal(value),
            Instruction::Concatenate { operands, .. } => {
                let mut combined = String::new();
                for operand in operands {
                    combined.push_str(&self.resolve_constant_string_inner(
                        *operand,
                        visited,
                        depth + 1,
                    )?);
                }
                Some(combined)
            }
            _ => None,
        }
    }
}

pub fn built_in_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(DangerousFunctionRule::new(
            "FERMIO-PHP-CORE-EVAL-001",
            "Dynamic code execution",
            &["eval"],
            Severity::Critical,
            "CWE-95",
        )),
        Box::new(DangerousFunctionRule::new(
            "FERMIO-PHP-CORE-CMD-001",
            "Operating system command execution",
            COMMAND_FUNCTIONS,
            Severity::High,
            "CWE-78",
        )),
        Box::new(DangerousFunctionRule::new(
            "FERMIO-PHP-CORE-DESERIALIZE-001",
            "Potentially unsafe deserialization",
            &["unserialize"],
            Severity::High,
            "CWE-502",
        )),
        Box::new(DangerousFunctionRule::new(
            "FERMIO-PHP-CORE-CRYPTO-001",
            "Weak cryptographic hash",
            &["md5", "sha1"],
            Severity::Medium,
            "CWE-328",
        )),
        Box::new(HardcodedSecretRule),
        Box::new(TaintedCommandRule),
    ]
}

struct DangerousFunctionRule {
    id: &'static str,
    title: &'static str,
    functions: &'static [&'static str],
    severity: Severity,
    cwe: &'static str,
}

impl DangerousFunctionRule {
    const fn new(
        id: &'static str,
        title: &'static str,
        functions: &'static [&'static str],
        severity: Severity,
        cwe: &'static str,
    ) -> Self {
        Self {
            id,
            title,
            functions,
            severity,
            cwe,
        }
    }

    fn matching_function(&self, target: &str) -> Option<&'static str> {
        let normalized = normalize_call(target);
        self.functions
            .iter()
            .copied()
            .find(|function| normalized.eq_ignore_ascii_case(function))
    }
}

impl Rule for DangerousFunctionRule {
    fn id(&self) -> &'static str {
        self.id
    }

    fn evaluate(&self, analysis: &ModuleAnalysis<'_>) -> Vec<Finding> {
        analysis
            .module()
            .instructions
            .iter()
            .filter_map(|instruction| match instruction {
                Instruction::Call {
                    target,
                    call_kind: CallKind::Function,
                    location,
                    ..
                } => self.matching_function(target).map(|function| Finding {
                    rule_id: self.id.to_string(),
                    title: self.title.to_string(),
                    description: format!("The PHP function `{function}` requires security review."),
                    severity: self.severity,
                    confidence: Confidence::High,
                    location: location.clone(),
                    fingerprint: fingerprint(self.id, function, location),
                    cwe: Some(self.cwe.to_string()),
                    framework: None,
                }),
                _ => None,
            })
            .collect()
    }
}

struct TaintedCommandRule;

impl Rule for TaintedCommandRule {
    fn id(&self) -> &'static str {
        "FERMIO-PHP-TAINT-CMD-001"
    }

    fn evaluate(&self, analysis: &ModuleAnalysis<'_>) -> Vec<Finding> {
        analysis
            .module()
            .instructions
            .iter()
            .filter_map(|instruction| match instruction {
                Instruction::Call {
                    target,
                    call_kind: CallKind::Function,
                    arguments,
                    location,
                    ..
                } if is_command_function(target) => {
                    let argument = arguments.first()?;
                    let fact = analysis.taint(*argument)?;
                    let function = normalize_call(target);
                    Some(Finding {
                        rule_id: self.id().to_string(),
                        title: "User-controlled command execution".to_string(),
                        description: format!(
                            "Data originating from `{}` reaches the PHP command execution function `{function}`.",
                            fact.source
                        ),
                        severity: Severity::Critical,
                        confidence: Confidence::High,
                        location: location.clone(),
                        fingerprint: fingerprint(
                            self.id(),
                            &format!("{function}:{}", fact.source),
                            location,
                        ),
                        cwe: Some("CWE-78".to_string()),
                        framework: None,
                    })
                }
                _ => None,
            })
            .collect()
    }
}

struct HardcodedSecretRule;

impl Rule for HardcodedSecretRule {
    fn id(&self) -> &'static str {
        "FERMIO-PHP-CORE-SECRET-001"
    }

    fn evaluate(&self, analysis: &ModuleAnalysis<'_>) -> Vec<Finding> {
        analysis
            .module()
            .instructions
            .iter()
            .filter_map(|instruction| match instruction {
                Instruction::Assignment {
                    target,
                    value,
                    location,
                } if is_secret_name(target) => {
                    let resolved = analysis.resolve_constant_string(*value)?;
                    if !is_likely_secret_value(&resolved) {
                        return None;
                    }

                    Some(Finding {
                        rule_id: self.id().to_string(),
                        title: "Likely hard-coded secret".to_string(),
                        description: format!(
                            "The variable `{target}` is assigned a non-empty hard-coded string. The value is redacted."
                        ),
                        severity: Severity::High,
                        confidence: Confidence::Medium,
                        location: location.clone(),
                        fingerprint: fingerprint(self.id(), target, location),
                        cwe: Some("CWE-798".to_string()),
                        framework: None,
                    })
                }
                _ => None,
            })
            .collect()
    }
}

fn instruction_output(instruction: &Instruction) -> Option<ValueId> {
    match instruction {
        Instruction::VariableRead { output, .. }
        | Instruction::Literal { output, .. }
        | Instruction::Concatenate { output, .. }
        | Instruction::IndexRead { output, .. }
        | Instruction::Call { output, .. }
        | Instruction::Opaque { output, .. } => Some(*output),
        Instruction::Assignment { .. } | Instruction::Return { .. } => None,
    }
}

fn normalize_string_literal(value: &str) -> Option<String> {
    let value = value.trim();
    let value = value
        .strip_prefix('b')
        .or_else(|| value.strip_prefix('B'))
        .unwrap_or(value);
    let bytes = value.as_bytes();

    if bytes.len() >= 2
        && ((bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\'')
            || (bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"'))
    {
        Some(value[1..value.len() - 1].to_string())
    } else if value.starts_with("<<<") {
        None
    } else {
        Some(value.to_string())
    }
}

fn normalize_call(target: &str) -> &str {
    target.trim().trim_start_matches('\\')
}

fn is_command_function(target: &str) -> bool {
    let target = normalize_call(target);
    COMMAND_FUNCTIONS
        .iter()
        .any(|function| target.eq_ignore_ascii_case(function))
}

fn is_untrusted_superglobal(name: &str) -> bool {
    matches!(
        name,
        "$_COOKIE" | "$_FILES" | "$_GET" | "$_POST" | "$_REQUEST" | "$_SERVER"
    )
}

fn is_secret_name(target: &str) -> bool {
    let normalized = target
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || *character == '_')
        .collect::<String>()
        .to_ascii_lowercase();

    [
        "access_token",
        "apikey",
        "api_key",
        "auth_token",
        "client_secret",
        "password",
        "passwd",
        "private_key",
        "secret",
    ]
    .iter()
    .any(|pattern| normalized.contains(pattern))
}

fn is_likely_secret_value(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.len() < 4 {
        return false;
    }

    ![
        "changeme",
        "change-me",
        "dummy",
        "example",
        "example-secret",
        "password",
        "replace-me",
        "secret",
        "test",
        "testing",
        "your-secret-here",
    ]
    .contains(&normalized.as_str())
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
            end_column: 12,
        }
    }

    fn call(target: &str, argument: ValueId, line: usize) -> Instruction {
        Instruction::Call {
            output: ValueId(100 + line as u32),
            target: target.to_string(),
            call_kind: CallKind::Function,
            arguments: vec![argument],
            location: location(line),
        }
    }

    #[test]
    fn resolves_constants_through_assignment_and_concatenation() {
        let module = ModuleIr {
            language: "php".to_string(),
            path: "src/example.php".to_string(),
            instructions: vec![
                Instruction::Literal {
                    output: ValueId(0),
                    value: LiteralValue::String("'abc'".to_string()),
                    location: location(1),
                },
                Instruction::Assignment {
                    target: "$prefix".to_string(),
                    value: ValueId(0),
                    location: location(1),
                },
                Instruction::VariableRead {
                    output: ValueId(1),
                    name: "$prefix".to_string(),
                    location: location(2),
                },
                Instruction::Literal {
                    output: ValueId(2),
                    value: LiteralValue::String("'def'".to_string()),
                    location: location(2),
                },
                Instruction::Concatenate {
                    output: ValueId(3),
                    operands: vec![ValueId(1), ValueId(2)],
                    location: location(2),
                },
            ],
        };

        assert_eq!(
            ModuleAnalysis::new(&module).resolve_constant_string(ValueId(3)),
            Some("abcdef".to_string())
        );
    }

    #[test]
    fn propagates_superglobal_taint_through_index_assignment_and_concat() {
        let module = ModuleIr {
            language: "php".to_string(),
            path: "src/example.php".to_string(),
            instructions: vec![
                Instruction::VariableRead {
                    output: ValueId(0),
                    name: "$_GET".to_string(),
                    location: location(1),
                },
                Instruction::IndexRead {
                    output: ValueId(1),
                    collection: ValueId(0),
                    index: None,
                    location: location(1),
                },
                Instruction::Assignment {
                    target: "$input".to_string(),
                    value: ValueId(1),
                    location: location(1),
                },
                Instruction::VariableRead {
                    output: ValueId(2),
                    name: "$input".to_string(),
                    location: location(2),
                },
                Instruction::Literal {
                    output: ValueId(3),
                    value: LiteralValue::String("'ls '".to_string()),
                    location: location(2),
                },
                Instruction::Concatenate {
                    output: ValueId(4),
                    operands: vec![ValueId(3), ValueId(2)],
                    location: location(2),
                },
            ],
        };

        assert_eq!(
            ModuleAnalysis::new(&module).taint(ValueId(4)),
            Some(&TaintFact {
                source: "$_GET".to_string()
            })
        );
    }

    #[test]
    fn reports_tainted_command_execution() {
        let module = ModuleIr {
            language: "php".to_string(),
            path: "src/example.php".to_string(),
            instructions: vec![
                Instruction::VariableRead {
                    output: ValueId(0),
                    name: "$_POST".to_string(),
                    location: location(1),
                },
                Instruction::IndexRead {
                    output: ValueId(1),
                    collection: ValueId(0),
                    index: None,
                    location: location(1),
                },
                call("system", ValueId(1), 2),
            ],
        };
        let findings = TaintedCommandRule.evaluate(&ModuleAnalysis::new(&module));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].description.contains("$_POST"));
    }

    #[test]
    fn does_not_report_constant_command_arguments_as_tainted() {
        let module = ModuleIr {
            language: "php".to_string(),
            path: "src/example.php".to_string(),
            instructions: vec![
                Instruction::Literal {
                    output: ValueId(0),
                    value: LiteralValue::String("'uptime'".to_string()),
                    location: location(1),
                },
                call("system", ValueId(0), 1),
            ],
        };

        assert!(TaintedCommandRule
            .evaluate(&ModuleAnalysis::new(&module))
            .is_empty());
    }

    #[test]
    fn ignores_method_calls_named_like_dangerous_functions() {
        let module = ModuleIr {
            language: "php".to_string(),
            path: "src/example.php".to_string(),
            instructions: vec![Instruction::Call {
                output: ValueId(0),
                target: "system".to_string(),
                call_kind: CallKind::Method,
                arguments: Vec::new(),
                location: location(1),
            }],
        };
        let analysis = ModuleAnalysis::new(&module);
        let rule = built_in_rules()
            .into_iter()
            .find(|rule| rule.id() == "FERMIO-PHP-CORE-CMD-001")
            .expect("command rule should exist");

        assert!(rule.evaluate(&analysis).is_empty());
    }

    #[test]
    fn hardcoded_secret_rule_redacts_the_value() {
        let module = ModuleIr {
            language: "php".to_string(),
            path: "src/example.php".to_string(),
            instructions: vec![
                Instruction::Literal {
                    output: ValueId(0),
                    value: LiteralValue::String("'sk_live_private_value'".to_string()),
                    location: location(1),
                },
                Instruction::Assignment {
                    target: "$api_key".to_string(),
                    value: ValueId(0),
                    location: location(1),
                },
            ],
        };
        let findings = HardcodedSecretRule.evaluate(&ModuleAnalysis::new(&module));

        assert_eq!(findings.len(), 1);
        assert!(!findings[0].description.contains("sk_live_private_value"));
    }

    #[test]
    fn fingerprint_does_not_change_when_line_moves() {
        let first = location(10);
        let moved = SourceLocation {
            start_line: 40,
            end_line: 40,
            ..first.clone()
        };

        assert_eq!(
            fingerprint("RULE-001", "system", &first),
            fingerprint("RULE-001", "system", &moved)
        );
    }
}

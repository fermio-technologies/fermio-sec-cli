use fermio_core::{Confidence, DataflowStep, Finding, Severity, SourceLocation};
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
const COMMAND_SANITIZERS: &[&str] = &["escapeshellarg", "escapeshellcmd"];

pub trait Rule: Send + Sync {
    fn id(&self) -> &'static str;
    fn evaluate(&self, analysis: &ModuleAnalysis<'_>) -> Vec<Finding>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintFact {
    pub source: String,
    pub steps: Vec<DataflowStep>,
}

impl TaintFact {
    fn propagated(&self, label: impl Into<String>, location: &SourceLocation) -> Self {
        let mut fact = self.clone();
        fact.steps.push(DataflowStep {
            label: label.into(),
            location: location.clone(),
        });
        fact
    }
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
                Instruction::VariableRead {
                    output,
                    name,
                    location,
                } => {
                    if is_untrusted_superglobal(name) {
                        taint.insert(
                            *output,
                            TaintFact {
                                source: name.clone(),
                                steps: vec![DataflowStep {
                                    label: format!("Untrusted input from `{name}`"),
                                    location: location.clone(),
                                }],
                            },
                        );
                    } else if let Some(value) = assignments.get(name) {
                        aliases.insert(*output, *value);
                        if let Some(fact) = taint.get(value) {
                            taint.insert(
                                *output,
                                fact.propagated(format!("Read from `{name}`"), location),
                            );
                        }
                    }
                }
                Instruction::Assignment {
                    target,
                    value,
                    location,
                } => {
                    assignments.insert(target.clone(), *value);
                    if let Some(fact) = taint.get(value).cloned() {
                        taint.insert(
                            *value,
                            fact.propagated(format!("Assigned to `{target}`"), location),
                        );
                    }
                }
                Instruction::Concatenate {
                    output,
                    operands,
                    location,
                } => {
                    if let Some(fact) = operands.iter().find_map(|value| taint.get(value)) {
                        taint.insert(*output, fact.propagated("String concatenation", location));
                    }
                }
                Instruction::IndexRead {
                    output,
                    collection,
                    location,
                    ..
                } => {
                    if let Some(fact) = taint.get(collection) {
                        taint.insert(*output, fact.propagated("Indexed value read", location));
                    }
                }
                Instruction::Call {
                    output,
                    target,
                    call_kind: CallKind::Function,
                    arguments,
                    ..
                } if is_command_sanitizer(target) => {
                    // Sanitizers intentionally terminate command taint propagation.
                    if arguments.first().is_some_and(|value| taint.contains_key(value)) {
                        taint.remove(output);
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
        visiting: &mut HashSet<ValueId>,
        depth: usize,
    ) -> Option<String> {
        if depth > 32 || !visiting.insert(value) {
            return None;
        }

        let resolved = if let Some(alias) = self.aliases.get(&value) {
            self.resolve_constant_string_inner(*alias, visiting, depth + 1)
        } else {
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
                            visiting,
                            depth + 1,
                        )?);
                    }
                    Some(combined)
                }
                _ => None,
            }
        };

        visiting.remove(&value);
        resolved
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
                    dataflow: Vec::new(),
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
                    let mut dataflow = fact.steps.clone();
                    dataflow.push(DataflowStep {
                        label: format!("Command execution sink `{function}`"),
                        location: location.clone(),
                    });
                    Some(Finding {
                        rule_id: self.id().to_string(),
                        title: "User-controlled command execution".to_string(),
                        description: format!(
                            "Data originating from `{}` reaches the PHP command execution function `{function}` without a recognized command sanitizer.",
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
                        dataflow,
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
                        dataflow: Vec::new(),
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
    let value = if value.starts_with("b'")
        || value.starts_with("B'")
        || value.starts_with("b\"")
        || value.starts_with("B\"")
    {
        &value[1..]
    } else {
        value
    };
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

fn is_command_sanitizer(target: &str) -> bool {
    let target = normalize_call(target);
    COMMAND_SANITIZERS
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

    fn call(output: u32, target: &str, argument: ValueId, line: usize) -> Instruction {
        Instruction::Call {
            output: ValueId(output),
            target: target.to_string(),
            call_kind: CallKind::Function,
            arguments: vec![argument],
            location: location(line),
        }
    }

    fn tainted_input() -> Vec<Instruction> {
        vec![
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
        ]
    }

    #[test]
    fn reports_tainted_command_with_dataflow() {
        let mut instructions = tainted_input();
        instructions.push(call(2, "system", ValueId(1), 2));
        let module = ModuleIr {
            language: "php".to_string(),
            path: "src/example.php".to_string(),
            instructions,
        };
        let findings = TaintedCommandRule.evaluate(&ModuleAnalysis::new(&module));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].dataflow.len() >= 3);
    }

    #[test]
    fn command_sanitizers_terminate_taint() {
        for sanitizer in COMMAND_SANITIZERS {
            let mut instructions = tainted_input();
            instructions.push(call(2, sanitizer, ValueId(1), 2));
            instructions.push(call(3, "system", ValueId(2), 3));
            let module = ModuleIr {
                language: "php".to_string(),
                path: "src/example.php".to_string(),
                instructions,
            };
            assert!(TaintedCommandRule
                .evaluate(&ModuleAnalysis::new(&module))
                .is_empty());
        }
    }

    #[test]
    fn resolves_repeated_constant_operands() {
        let module = ModuleIr {
            language: "php".to_string(),
            path: "src/example.php".to_string(),
            instructions: vec![
                Instruction::Literal {
                    output: ValueId(0),
                    value: LiteralValue::String("'a'".to_string()),
                    location: location(1),
                },
                Instruction::Concatenate {
                    output: ValueId(1),
                    operands: vec![ValueId(0), ValueId(0)],
                    location: location(1),
                },
            ],
        };
        assert_eq!(
            ModuleAnalysis::new(&module).resolve_constant_string(ValueId(1)),
            Some("aa".to_string())
        );
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
}

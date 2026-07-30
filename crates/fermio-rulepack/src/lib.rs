use anyhow::{bail, Context, Result};
use fermio_core::{Confidence, Finding, Severity, SourceLocation};
use fermio_ir::{CallKind, Instruction, ValueId};
use fermio_rules::{ModuleAnalysis, Rule};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs, path::Path};

pub const RULEPACK_SCHEMA_VERSION: u32 = 1;
pub const MAX_RULEPACK_BYTES: u64 = 1024 * 1024;
pub const MAX_RULES_PER_PACK: usize = 1_000;

const BUILTIN_FRAMEWORK_RULEPACK: &str = include_str!("../../../rulepacks/php-frameworks.toml");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RulepackDefinition {
    schema_version: u32,
    id: String,
    version: String,
    rules: Vec<RuleDefinition>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleDefinition {
    id: String,
    title: String,
    description: String,
    severity: Severity,
    confidence: Confidence,
    cwe: Option<String>,
    #[serde(default)]
    frameworks: Vec<String>,
    targets: Vec<String>,
    #[serde(default = "default_call_kinds")]
    call_kinds: Vec<RuleCallKind>,
    argument: Option<ArgumentMatcher>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RuleCallKind {
    Function,
    Method,
    NullsafeMethod,
    StaticMethod,
    Dynamic,
}

impl RuleCallKind {
    fn matches(self, call_kind: CallKind) -> bool {
        matches!(
            (self, call_kind),
            (Self::Function, CallKind::Function)
                | (Self::Method, CallKind::Method)
                | (Self::NullsafeMethod, CallKind::NullsafeMethod)
                | (Self::StaticMethod, CallKind::StaticMethod)
                | (Self::Dynamic, CallKind::Dynamic)
        )
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArgumentMatcher {
    index: usize,
    string_equals: Option<String>,
    string_prefix: Option<String>,
    case_sensitive: Option<bool>,
}

impl ArgumentMatcher {
    fn matches(&self, actual: &str) -> bool {
        let case_sensitive = self.case_sensitive.unwrap_or(true);
        if let Some(expected) = &self.string_equals {
            return compare(actual, expected, case_sensitive, |left, right| {
                left == right
            });
        }
        if let Some(prefix) = &self.string_prefix {
            return compare(actual, prefix, case_sensitive, |left, right| {
                left.starts_with(right)
            });
        }
        false
    }
}

fn compare(
    actual: &str,
    expected: &str,
    case_sensitive: bool,
    operation: impl FnOnce(&str, &str) -> bool,
) -> bool {
    if case_sensitive {
        operation(actual, expected)
    } else {
        operation(&actual.to_ascii_lowercase(), &expected.to_ascii_lowercase())
    }
}

struct DeclarativeCallRule {
    id: &'static str,
    title: String,
    description: String,
    severity: Severity,
    confidence: Confidence,
    cwe: Option<String>,
    frameworks: Vec<String>,
    active: bool,
    targets: Vec<String>,
    call_kinds: Vec<RuleCallKind>,
    argument: Option<ArgumentMatcher>,
}

impl Rule for DeclarativeCallRule {
    fn id(&self) -> &'static str {
        self.id
    }

    fn evaluate(&self, analysis: &ModuleAnalysis<'_>) -> Vec<Finding> {
        if !self.active {
            return Vec::new();
        }

        analysis
            .module()
            .instructions
            .iter()
            .filter_map(|instruction| match instruction {
                Instruction::Call {
                    target,
                    call_kind,
                    arguments,
                    location,
                    ..
                } if self.matches_call(target, *call_kind, arguments, analysis) => {
                    let semantic_target = normalize_target(target);
                    Some(Finding {
                        rule_id: self.id.to_string(),
                        title: self.title.clone(),
                        description: self.description.clone(),
                        severity: self.severity,
                        confidence: self.confidence,
                        location: location.clone(),
                        fingerprint: fingerprint(self.id, &semantic_target, location),
                        cwe: self.cwe.clone(),
                        framework: self.single_framework(),
                        dataflow: Vec::new(),
                    })
                }
                _ => None,
            })
            .collect()
    }
}

impl DeclarativeCallRule {
    fn matches_call(
        &self,
        target: &str,
        call_kind: CallKind,
        arguments: &[ValueId],
        analysis: &ModuleAnalysis<'_>,
    ) -> bool {
        if !self
            .call_kinds
            .iter()
            .any(|expected| expected.matches(call_kind))
        {
            return false;
        }

        let normalized = normalize_target(target);
        if !self.targets.iter().any(|expected| expected == &normalized) {
            return false;
        }

        let Some(matcher) = &self.argument else {
            return true;
        };
        let Some(argument) = arguments.get(matcher.index) else {
            return false;
        };
        analysis
            .resolve_constant_string(*argument)
            .is_some_and(|actual| matcher.matches(&actual))
    }

    fn single_framework(&self) -> Option<String> {
        (self.frameworks.len() == 1).then(|| self.frameworks[0].clone())
    }
}

pub fn built_in_rules(active_frameworks: &[String]) -> Result<Vec<Box<dyn Rule>>> {
    parse_rulepack(BUILTIN_FRAMEWORK_RULEPACK, active_frameworks)
        .context("invalid built-in PHP framework rulepack")
}

pub fn load_rulepack_file(path: &Path, active_frameworks: &[String]) -> Result<Vec<Box<dyn Rule>>> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("failed to inspect rulepack {}", path.display()))?;
    if metadata.len() > MAX_RULEPACK_BYTES {
        bail!(
            "rulepack {} exceeds the {} byte size limit",
            path.display(),
            MAX_RULEPACK_BYTES
        );
    }

    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read rulepack {}", path.display()))?;
    parse_rulepack(&content, active_frameworks)
        .with_context(|| format!("invalid rulepack {}", path.display()))
}

pub fn parse_rulepack(content: &str, active_frameworks: &[String]) -> Result<Vec<Box<dyn Rule>>> {
    let pack: RulepackDefinition = toml::from_str(content).context("invalid rulepack TOML")?;
    validate_rulepack(&pack)?;

    Ok(pack
        .rules
        .into_iter()
        .map(|rule| instantiate_rule(rule, active_frameworks))
        .collect())
}

fn instantiate_rule(rule: RuleDefinition, active_frameworks: &[String]) -> Box<dyn Rule> {
    let active = rule.frameworks.is_empty()
        || rule.frameworks.iter().any(|required| {
            active_frameworks
                .iter()
                .any(|actual| actual.eq_ignore_ascii_case(required))
        });
    let id = Box::leak(rule.id.into_boxed_str());
    Box::new(DeclarativeCallRule {
        id,
        title: rule.title,
        description: rule.description,
        severity: rule.severity,
        confidence: rule.confidence,
        cwe: rule.cwe,
        frameworks: rule.frameworks,
        active,
        targets: rule
            .targets
            .into_iter()
            .map(|target| normalize_target(&target))
            .collect(),
        call_kinds: rule.call_kinds,
        argument: rule.argument,
    })
}

fn validate_rulepack(pack: &RulepackDefinition) -> Result<()> {
    if pack.schema_version != RULEPACK_SCHEMA_VERSION {
        bail!(
            "unsupported rulepack schema version {}; expected {}",
            pack.schema_version,
            RULEPACK_SCHEMA_VERSION
        );
    }
    if pack.id.trim().is_empty() {
        bail!("rulepack id cannot be empty");
    }
    if pack.version.trim().is_empty() {
        bail!("rulepack version cannot be empty");
    }
    if pack.rules.is_empty() {
        bail!("rulepack must contain at least one rule");
    }
    if pack.rules.len() > MAX_RULES_PER_PACK {
        bail!(
            "rulepack contains {} rules, exceeding the limit of {}",
            pack.rules.len(),
            MAX_RULES_PER_PACK
        );
    }

    let mut ids = BTreeSet::new();
    for rule in &pack.rules {
        validate_rule(rule)?;
        if !ids.insert(rule.id.as_str()) {
            bail!("rulepack contains duplicate rule id `{}`", rule.id);
        }
    }
    Ok(())
}

fn validate_rule(rule: &RuleDefinition) -> Result<()> {
    if !is_valid_rule_id(&rule.id) {
        bail!(
            "rule id `{}` must start with FERMIO- and contain only uppercase ASCII letters, digits and hyphens",
            rule.id
        );
    }
    if rule.title.trim().is_empty() {
        bail!("rule `{}` has an empty title", rule.id);
    }
    if rule.description.trim().is_empty() {
        bail!("rule `{}` has an empty description", rule.id);
    }
    if rule.targets.is_empty() {
        bail!("rule `{}` must define at least one call target", rule.id);
    }
    if rule.call_kinds.is_empty() {
        bail!("rule `{}` must define at least one call kind", rule.id);
    }

    validate_unique_values(&rule.id, "targets", &rule.targets, true)?;
    validate_unique_values(&rule.id, "frameworks", &rule.frameworks, false)?;

    if let Some(cwe) = &rule.cwe {
        if !is_valid_cwe(cwe) {
            bail!("rule `{}` has invalid CWE identifier `{cwe}`", rule.id);
        }
    }

    if let Some(argument) = &rule.argument {
        let matchers = usize::from(argument.string_equals.is_some())
            + usize::from(argument.string_prefix.is_some());
        if matchers != 1 {
            bail!(
                "rule `{}` argument matcher must define exactly one of string_equals or string_prefix",
                rule.id
            );
        }
        if argument.index > 31 {
            bail!("rule `{}` argument index exceeds the limit of 31", rule.id);
        }
        if argument
            .string_equals
            .as_deref()
            .or(argument.string_prefix.as_deref())
            .is_some_and(str::is_empty)
        {
            bail!("rule `{}` argument matcher cannot be empty", rule.id);
        }
    }

    Ok(())
}

fn validate_unique_values(
    rule_id: &str,
    field: &str,
    values: &[String],
    normalize_as_target: bool,
) -> Result<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        if value.trim().is_empty() {
            bail!("rule `{rule_id}` contains an empty {field} value");
        }
        let normalized = if normalize_as_target {
            normalize_target(value)
        } else {
            value.trim().to_ascii_lowercase()
        };
        if !seen.insert(normalized) {
            bail!("rule `{rule_id}` contains duplicate {field} value `{value}`");
        }
    }
    Ok(())
}

fn is_valid_rule_id(value: &str) -> bool {
    value.starts_with("FERMIO-")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
}

fn is_valid_cwe(value: &str) -> bool {
    value.strip_prefix("CWE-").is_some_and(|digits| {
        !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn default_call_kinds() -> Vec<RuleCallKind> {
    vec![RuleCallKind::Function]
}

fn normalize_target(target: &str) -> String {
    target.trim().trim_start_matches('\\').to_ascii_lowercase()
}

fn fingerprint(rule_id: &str, semantic_target: &str, location: &SourceLocation) -> String {
    let normalized_path = location.path.to_string_lossy().replace('\\', "/");
    let mut hasher = Sha256::new();
    hasher.update(rule_id.as_bytes());
    hasher.update([0]);
    hasher.update(normalized_path.as_bytes());
    hasher.update([0]);
    hasher.update(semantic_target.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fermio_ir::{LiteralValue, ModuleIr};

    fn location(line: usize) -> SourceLocation {
        SourceLocation {
            path: "src/example.php".into(),
            start_line: line,
            start_column: 1,
            end_line: line,
            end_column: 20,
        }
    }

    fn call_module(target: &str, call_kind: CallKind, literal: Option<&str>) -> ModuleIr {
        let mut instructions = Vec::new();
        let arguments = if let Some(value) = literal {
            instructions.push(Instruction::Literal {
                output: ValueId(0),
                value: LiteralValue::String(format!("'{value}'")),
                location: location(1),
            });
            vec![ValueId(0)]
        } else {
            Vec::new()
        };
        instructions.push(Instruction::Call {
            output: ValueId(1),
            target: target.to_string(),
            call_kind,
            arguments,
            location: location(2),
        });
        ModuleIr {
            language: "php".to_string(),
            path: "src/example.php".to_string(),
            instructions,
        }
    }

    #[test]
    fn activates_rules_only_for_detected_frameworks() {
        let rules = built_in_rules(&["laravel".to_string()]).expect("built-ins should parse");
        let laravel = rules
            .iter()
            .find(|rule| rule.id() == "FERMIO-LARAVEL-DEBUG-DD-001")
            .expect("Laravel rule should exist");
        let symfony = rules
            .iter()
            .find(|rule| rule.id() == "FERMIO-SYMFONY-PROCESS-SHELL-001")
            .expect("Symfony rule should exist");
        let module = call_module("dd", CallKind::Function, None);
        let analysis = ModuleAnalysis::new(&module);
        assert_eq!(laravel.evaluate(&analysis).len(), 1);
        assert!(symfony.evaluate(&analysis).is_empty());
    }

    #[test]
    fn matches_literal_argument_prefix() {
        let rules = built_in_rules(&["wordpress".to_string()]).expect("built-ins should parse");
        let rule = rules
            .iter()
            .find(|rule| rule.id() == "FERMIO-WORDPRESS-AJAX-NOPRIV-001")
            .expect("WordPress rule should exist");
        let module = call_module(
            "add_action",
            CallKind::Function,
            Some("wp_ajax_nopriv_export_data"),
        );
        let findings = rule.evaluate(&ModuleAnalysis::new(&module));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].framework.as_deref(), Some("wordpress"));
    }

    #[test]
    fn rejects_duplicate_rule_ids() {
        let content = r#"
            schema_version = 1
            id = "test.pack"
            version = "1.0.0"

            [[rules]]
            id = "FERMIO-TEST-001"
            title = "Test"
            description = "Test rule"
            severity = "low"
            confidence = "high"
            targets = ["test"]

            [[rules]]
            id = "FERMIO-TEST-001"
            title = "Duplicate"
            description = "Duplicate rule"
            severity = "low"
            confidence = "high"
            targets = ["duplicate"]
        "#;
        let error = parse_rulepack(content, &[])
            .err()
            .expect("duplicate IDs must fail");
        assert!(error.to_string().contains("duplicate rule id"));
    }

    #[test]
    fn rejects_unknown_fields() {
        let content = r#"
            schema_version = 1
            id = "test.pack"
            version = "1.0.0"
            unknown = true
            rules = []
        "#;
        let error = parse_rulepack(content, &[])
            .err()
            .expect("unknown fields must fail");
        assert!(error.to_string().contains("invalid rulepack TOML"));
    }
}

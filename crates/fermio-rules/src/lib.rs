use fermio_core::{Confidence, Finding, Severity};
use fermio_ir::{Instruction, ModuleIr};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

pub trait Rule: Send + Sync {
    fn id(&self) -> &'static str;
    fn evaluate(&self, module: &ModuleIr) -> Vec<Finding>;
}

pub fn built_in_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(DangerousFunctionRule::new(
            "FERMIO-PHP-CORE-EVAL-001",
            "Dynamic code execution",
            "eval",
            Severity::Critical,
            "CWE-95",
        )),
        Box::new(DangerousFunctionRule::new(
            "FERMIO-PHP-CORE-CMD-001",
            "Operating system command execution",
            "system",
            Severity::High,
            "CWE-78",
        )),
        Box::new(DangerousFunctionRule::new(
            "FERMIO-PHP-CORE-DESERIALIZE-001",
            "Potentially unsafe deserialization",
            "unserialize",
            Severity::High,
            "CWE-502",
        )),
        Box::new(DangerousFunctionRule::new(
            "FERMIO-PHP-CORE-CRYPTO-001",
            "Weak cryptographic hash",
            "md5",
            Severity::Medium,
            "CWE-328",
        )),
    ]
}

struct DangerousFunctionRule {
    id: &'static str,
    title: &'static str,
    function: &'static str,
    severity: Severity,
    cwe: &'static str,
}

impl DangerousFunctionRule {
    const fn new(
        id: &'static str,
        title: &'static str,
        function: &'static str,
        severity: Severity,
        cwe: &'static str,
    ) -> Self {
        Self {
            id,
            title,
            function,
            severity,
            cwe,
        }
    }
}

impl Rule for DangerousFunctionRule {
    fn id(&self) -> &'static str {
        self.id
    }

    fn evaluate(&self, module: &ModuleIr) -> Vec<Finding> {
        module
            .instructions
            .iter()
            .filter_map(|instruction| match instruction {
                Instruction::Call {
                    target, location, ..
                } if normalize_call(target) == self.function => Some(Finding {
                    rule_id: self.id.to_string(),
                    title: self.title.to_string(),
                    description: format!(
                        "The PHP function `{}` requires security review.",
                        self.function
                    ),
                    severity: self.severity,
                    confidence: Confidence::High,
                    location: location.clone(),
                    fingerprint: fingerprint(self.id, location),
                    cwe: Some(self.cwe.to_string()),
                    framework: None,
                }),
                _ => None,
            })
            .collect()
    }
}

fn normalize_call(target: &str) -> &str {
    target.trim_start_matches('\\')
}

fn fingerprint(rule_id: &str, location: &fermio_core::SourceLocation) -> String {
    let mut hasher = DefaultHasher::new();
    rule_id.hash(&mut hasher);
    location.path.hash(&mut hasher);
    location.start_line.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

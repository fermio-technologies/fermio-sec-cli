use fermio_core::{Confidence, Finding, Severity};
use fermio_ir::{Instruction, ModuleIr};
use sha2::{Digest, Sha256};

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
                    fingerprint: fingerprint(self.id, target, location),
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

fn fingerprint(
    rule_id: &str,
    semantic_anchor: &str,
    location: &fermio_core::SourceLocation,
) -> String {
    let normalized_path = location.path.to_string_lossy().replace('\\', "/");
    let mut hasher = Sha256::new();
    hasher.update(rule_id.as_bytes());
    hasher.update([0]);
    hasher.update(normalized_path.as_bytes());
    hasher.update([0]);
    hasher.update(normalize_call(semantic_anchor).as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fermio_core::SourceLocation;

    #[test]
    fn fingerprint_does_not_change_when_line_moves() {
        let first = SourceLocation {
            path: "src/example.php".into(),
            start_line: 10,
            start_column: 1,
            end_line: 10,
            end_column: 12,
        };
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

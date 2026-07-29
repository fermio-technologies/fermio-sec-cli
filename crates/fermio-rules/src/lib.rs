use fermio_core::{Confidence, DataflowStep, Finding, Severity, SourceLocation};
use fermio_ir::{CallKind, Instruction, LiteralValue, ModuleIr, OutputKind, ValueId};
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
const HTML_SANITIZERS: &[&str] = &["htmlentities", "htmlspecialchars"];
const SUMMARY_SOURCE_PREFIX: &str = "__fermio_parameter_";

pub trait Rule: Send + Sync {
    fn id(&self) -> &'static str;
    fn evaluate(&self, analysis: &ModuleAnalysis<'_>) -> Vec<Finding>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum TaintDomain {
    Command,
    Html,
    Sql,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintFact {
    pub source: String,
    pub steps: Vec<DataflowStep>,
    sanitized_for: HashSet<TaintDomain>,
}

impl TaintFact {
    fn source(source: String, location: &SourceLocation) -> Self {
        Self {
            steps: vec![DataflowStep {
                label: format!("Untrusted input from `{source}`"),
                location: location.clone(),
            }],
            source,
            sanitized_for: HashSet::new(),
        }
    }

    fn parameter(index: usize, name: &str, location: &SourceLocation) -> Self {
        Self {
            source: format!("{SUMMARY_SOURCE_PREFIX}{index}"),
            steps: vec![DataflowStep {
                label: format!("Function parameter `{name}`"),
                location: location.clone(),
            }],
            sanitized_for: HashSet::new(),
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

    fn sanitized(
        &self,
        domain: TaintDomain,
        label: impl Into<String>,
        location: &SourceLocation,
    ) -> Self {
        let mut fact = self.propagated(label, location);
        fact.sanitized_for.insert(domain);
        fact
    }

    fn is_active_for(&self, domain: TaintDomain) -> bool {
        !self.sanitized_for.contains(&domain)
    }

    fn merge(facts: Vec<Self>) -> Option<Self> {
        let mut facts = facts.into_iter();
        let mut merged = facts.next()?;
        for fact in facts {
            merged
                .sanitized_for
                .retain(|domain| fact.sanitized_for.contains(domain));
        }
        Some(merged)
    }

    fn merge_for_concatenation(facts: Vec<Self>, location: &SourceLocation) -> Option<Self> {
        Self::merge(facts).map(|fact| fact.propagated("String concatenation", location))
    }
}

#[derive(Debug, Clone)]
struct FunctionRegion<'a> {
    name: String,
    parameters: Vec<String>,
    instructions: Vec<&'a Instruction>,
    location: SourceLocation,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct FunctionSummary {
    dependencies: Vec<ReturnDependency>,
    intrinsic_returns: Vec<TaintFact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReturnDependency {
    parameter_index: usize,
    sanitized_for: HashSet<TaintDomain>,
    steps: Vec<DataflowStep>,
}

#[derive(Debug, Default)]
struct ScopeResult {
    aliases: HashMap<ValueId, ValueId>,
    taint: HashMap<ValueId, TaintFact>,
}

pub struct ModuleAnalysis<'a> {
    module: &'a ModuleIr,
    producers: HashMap<ValueId, &'a Instruction>,
    aliases: HashMap<ValueId, ValueId>,
    taint: HashMap<ValueId, TaintFact>,
}

impl<'a> ModuleAnalysis<'a> {
    pub fn new(module: &'a ModuleIr) -> Self {
        let (top_level, functions) = split_scopes(module);
        let summaries = build_function_summaries(&functions);

        let mut producers = HashMap::new();
        for instruction in &module.instructions {
            if let Some(output) = instruction_output(instruction) {
                producers.insert(output, instruction);
            }
        }

        let mut aliases = HashMap::new();
        let mut taint = HashMap::new();

        let top_level_result = analyze_scope(&top_level, &summaries, HashMap::new());
        aliases.extend(top_level_result.aliases);
        taint.extend(top_level_result.taint);

        for function in &functions {
            let result = analyze_scope(&function.instructions, &summaries, HashMap::new());
            aliases.extend(result.aliases);
            taint.extend(result.taint);
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

    fn taint_for(&self, value: ValueId, domain: TaintDomain) -> Option<&TaintFact> {
        self.taint(value).filter(|fact| fact.is_active_for(domain))
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

fn split_scopes<'a>(module: &'a ModuleIr) -> (Vec<&'a Instruction>, Vec<FunctionRegion<'a>>) {
    struct RegionBuilder<'a> {
        name: String,
        parameters: Vec<String>,
        instructions: Vec<&'a Instruction>,
        location: SourceLocation,
    }

    let mut top_level = Vec::new();
    let mut functions = Vec::new();
    let mut stack = Vec::<RegionBuilder<'a>>::new();

    for instruction in &module.instructions {
        match instruction {
            Instruction::FunctionStart {
                name,
                parameters,
                location,
            } => stack.push(RegionBuilder {
                name: name.clone(),
                parameters: parameters.clone(),
                instructions: Vec::new(),
                location: location.clone(),
            }),
            Instruction::FunctionEnd { .. } => {
                if let Some(region) = stack.pop() {
                    functions.push(FunctionRegion {
                        name: region.name,
                        parameters: region.parameters,
                        instructions: region.instructions,
                        location: region.location,
                    });
                }
            }
            _ => {
                if let Some(region) = stack.last_mut() {
                    region.instructions.push(instruction);
                } else {
                    top_level.push(instruction);
                }
            }
        }
    }

    functions.reverse();
    (top_level, functions)
}

fn build_function_summaries(
    functions: &[FunctionRegion<'_>],
) -> HashMap<String, FunctionSummary> {
    let mut summaries = HashMap::new();

    for _ in 0..=functions.len() {
        let mut changed = false;
        for function in functions {
            let key = normalized_call_name(&function.name);
            let summary = summarize_function(function, &summaries);
            if summaries.get(&key) != Some(&summary) {
                summaries.insert(key, summary);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    summaries
}

fn summarize_function(
    function: &FunctionRegion<'_>,
    summaries: &HashMap<String, FunctionSummary>,
) -> FunctionSummary {
    let mut dependencies = Vec::new();

    for (parameter_index, parameter) in function.parameters.iter().enumerate() {
        let mut initial_variables = HashMap::new();
        initial_variables.insert(
            parameter.clone(),
            TaintFact::parameter(parameter_index, parameter, &function.location),
        );
        let result = analyze_scope(&function.instructions, summaries, initial_variables);
        let source = format!("{SUMMARY_SOURCE_PREFIX}{parameter_index}");
        let facts = return_facts(&function.instructions, &result.taint)
            .into_iter()
            .filter(|fact| fact.source == source)
            .cloned()
            .collect::<Vec<_>>();

        if let Some(dependency) = summarize_return_dependency(parameter_index, facts) {
            dependencies.push(dependency);
        }
    }

    let intrinsic_result = analyze_scope(&function.instructions, summaries, HashMap::new());
    let mut intrinsic_returns = Vec::new();
    for fact in return_facts(&function.instructions, &intrinsic_result.taint) {
        if fact.source.starts_with(SUMMARY_SOURCE_PREFIX)
            || intrinsic_returns
                .iter()
                .any(|existing: &TaintFact| existing.source == fact.source)
        {
            continue;
        }
        intrinsic_returns.push(fact.clone());
    }

    FunctionSummary {
        dependencies,
        intrinsic_returns,
    }
}

fn summarize_return_dependency(
    parameter_index: usize,
    facts: Vec<TaintFact>,
) -> Option<ReturnDependency> {
    let mut facts = facts.into_iter();
    let first = facts.next()?;
    let mut sanitized_for = first.sanitized_for.clone();
    for fact in facts {
        sanitized_for.retain(|domain| fact.sanitized_for.contains(domain));
    }

    Some(ReturnDependency {
        parameter_index,
        sanitized_for,
        steps: first.steps,
    })
}

fn return_facts<'a>(
    instructions: &[&Instruction],
    taint: &'a HashMap<ValueId, TaintFact>,
) -> Vec<&'a TaintFact> {
    instructions
        .iter()
        .filter_map(|instruction| match instruction {
            Instruction::Return {
                value: Some(value), ..
            } => taint.get(value),
            _ => None,
        })
        .collect()
}

fn analyze_scope(
    instructions: &[&Instruction],
    summaries: &HashMap<String, FunctionSummary>,
    initial_variables: HashMap<String, TaintFact>,
) -> ScopeResult {
    let mut aliases = HashMap::new();
    let mut taint = HashMap::new();
    let mut assignments = HashMap::<String, ValueId>::new();

    for instruction in instructions {
        match instruction {
            Instruction::VariableRead {
                output,
                name,
                location,
            } => {
                if is_untrusted_superglobal(name) {
                    taint.insert(*output, TaintFact::source(name.clone(), location));
                } else if let Some(value) = assignments.get(name) {
                    aliases.insert(*output, *value);
                    if let Some(fact) = taint.get(value) {
                        taint.insert(
                            *output,
                            fact.propagated(format!("Read from `{name}`"), location),
                        );
                    }
                } else if let Some(fact) = initial_variables.get(name) {
                    taint.insert(
                        *output,
                        fact.propagated(format!("Read from parameter `{name}`"), location),
                    );
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
                let facts = operands
                    .iter()
                    .filter_map(|value| taint.get(value).cloned())
                    .collect::<Vec<_>>();
                if let Some(fact) = TaintFact::merge_for_concatenation(facts, location) {
                    taint.insert(*output, fact);
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
                location,
            } => {
                if let Some(argument) = command_sanitizer_argument(target, arguments) {
                    if let Some(fact) = taint.get(&argument) {
                        taint.insert(
                            *output,
                            fact.sanitized(
                                TaintDomain::Command,
                                format!(
                                    "Sanitized for shell command use by `{}`",
                                    normalize_call(target)
                                ),
                                location,
                            ),
                        );
                    }
                } else if let Some(argument) = html_sanitizer_argument(target, arguments) {
                    if let Some(fact) = taint.get(&argument) {
                        taint.insert(
                            *output,
                            fact.sanitized(
                                TaintDomain::Html,
                                format!(
                                    "Encoded for HTML output by `{}`",
                                    normalize_call(target)
                                ),
                                location,
                            ),
                        );
                    }
                } else if let Some(argument) = sql_sanitizer_argument(target, arguments) {
                    if let Some(fact) = taint.get(&argument) {
                        taint.insert(
                            *output,
                            fact.sanitized(
                                TaintDomain::Sql,
                                format!(
                                    "Sanitized for SQL string use by `{}`",
                                    normalize_call(target)
                                ),
                                location,
                            ),
                        );
                    }
                } else if let Some(summary) = summaries.get(&normalized_call_name(target)) {
                    if let Some(fact) =
                        apply_function_summary(summary, target, arguments, &taint, location)
                    {
                        taint.insert(*output, fact);
                    }
                }
            }
            _ => {}
        }
    }

    ScopeResult { aliases, taint }
}

fn apply_function_summary(
    summary: &FunctionSummary,
    target: &str,
    arguments: &[ValueId],
    taint: &HashMap<ValueId, TaintFact>,
    location: &SourceLocation,
) -> Option<TaintFact> {
    let mut candidates = Vec::new();

    for dependency in &summary.dependencies {
        let argument = arguments.get(dependency.parameter_index)?;
        if let Some(actual) = taint.get(argument) {
            let mut propagated = actual.clone();
            propagated
                .steps
                .extend(dependency.steps.iter().skip(1).cloned());
            propagated
                .sanitized_for
                .extend(dependency.sanitized_for.iter().copied());
            propagated.steps.push(DataflowStep {
                label: format!("Returned from function `{}`", normalize_call(target)),
                location: location.clone(),
            });
            candidates.push(propagated);
        }
    }

    for intrinsic in &summary.intrinsic_returns {
        candidates.push(intrinsic.propagated(
            format!("Returned from function `{}`", normalize_call(target)),
            location,
        ));
    }

    TaintFact::merge(candidates)
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
        Box::new(TaintedSqlRule),
        Box::new(TaintedHtmlOutputRule),
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
                    let argument = *arguments.first()?;
                    let fact = analysis.taint_for(argument, TaintDomain::Command)?;
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

struct TaintedSqlRule;

impl Rule for TaintedSqlRule {
    fn id(&self) -> &'static str {
        "FERMIO-PHP-TAINT-SQL-001"
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
                } => {
                    let argument = sql_sink_argument(target, arguments)?;
                    let fact = analysis.taint_for(argument, TaintDomain::Sql)?;
                    let function = normalize_call(target);
                    let mut dataflow = fact.steps.clone();
                    dataflow.push(DataflowStep {
                        label: format!("SQL query sink `{function}`"),
                        location: location.clone(),
                    });
                    Some(Finding {
                        rule_id: self.id().to_string(),
                        title: "User-controlled SQL query".to_string(),
                        description: format!(
                            "Data originating from `{}` reaches the PHP SQL query function `{function}` without a recognized SQL sanitizer or a fixed query boundary.",
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
                        cwe: Some("CWE-89".to_string()),
                        framework: None,
                        dataflow,
                    })
                }
                _ => None,
            })
            .collect()
    }
}

struct TaintedHtmlOutputRule;

impl Rule for TaintedHtmlOutputRule {
    fn id(&self) -> &'static str {
        "FERMIO-PHP-TAINT-XSS-001"
    }

    fn evaluate(&self, analysis: &ModuleAnalysis<'_>) -> Vec<Finding> {
        analysis
            .module()
            .instructions
            .iter()
            .filter_map(|instruction| match instruction {
                Instruction::Output {
                    output_kind,
                    values,
                    location,
                    ..
                } => {
                    let fact = values
                        .iter()
                        .find_map(|value| analysis.taint_for(*value, TaintDomain::Html))?;
                    let sink = output_kind_name(*output_kind);
                    let mut dataflow = fact.steps.clone();
                    dataflow.push(DataflowStep {
                        label: format!("HTML output sink `{sink}`"),
                        location: location.clone(),
                    });
                    Some(Finding {
                        rule_id: self.id().to_string(),
                        title: "User-controlled HTML output".to_string(),
                        description: format!(
                            "Data originating from `{}` reaches PHP `{sink}` output without recognized HTML encoding.",
                            fact.source
                        ),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        location: location.clone(),
                        fingerprint: fingerprint(
                            self.id(),
                            &format!("{sink}:{}", fact.source),
                            location,
                        ),
                        cwe: Some("CWE-79".to_string()),
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
        Instruction::Output { output, .. } => *output,
        Instruction::FunctionStart { .. }
        | Instruction::FunctionEnd { .. }
        | Instruction::Assignment { .. }
        | Instruction::Return { .. } => None,
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

fn normalized_call_name(target: &str) -> String {
    normalize_call(target).to_ascii_lowercase()
}

fn output_kind_name(output_kind: OutputKind) -> &'static str {
    match output_kind {
        OutputKind::Echo => "echo",
        OutputKind::Print => "print",
    }
}

fn is_command_function(target: &str) -> bool {
    let target = normalize_call(target);
    COMMAND_FUNCTIONS
        .iter()
        .any(|function| target.eq_ignore_ascii_case(function))
}

fn command_sanitizer_argument(target: &str, arguments: &[ValueId]) -> Option<ValueId> {
    let target = normalize_call(target);
    COMMAND_SANITIZERS
        .iter()
        .any(|function| target.eq_ignore_ascii_case(function))
        .then(|| arguments.first().copied())
        .flatten()
}

fn html_sanitizer_argument(target: &str, arguments: &[ValueId]) -> Option<ValueId> {
    let target = normalize_call(target);
    HTML_SANITIZERS
        .iter()
        .any(|function| target.eq_ignore_ascii_case(function))
        .then(|| arguments.first().copied())
        .flatten()
}

fn sql_sanitizer_argument(target: &str, arguments: &[ValueId]) -> Option<ValueId> {
    match normalized_call_name(target).as_str() {
        "mysql_real_escape_string" => arguments.first().copied(),
        "mysqli_escape_string" | "mysqli_real_escape_string" => arguments.get(1).copied(),
        "pg_escape_identifier" | "pg_escape_literal" | "pg_escape_string" => {
            arguments.last().copied()
        }
        _ => None,
    }
}

fn sql_sink_argument(target: &str, arguments: &[ValueId]) -> Option<ValueId> {
    match normalized_call_name(target).as_str() {
        "mysql_query" => arguments.first().copied(),
        "mysqli_execute_query" | "mysqli_multi_query" | "mysqli_query"
        | "mysqli_real_query" | "odbc_exec" | "sqlsrv_prepare" | "sqlsrv_query" => {
            arguments.get(1).copied()
        }
        "pg_prepare" | "pg_query" | "pg_send_query" => arguments.last().copied(),
        "pg_query_params" | "pg_send_query_params" => {
            if arguments.len() >= 3 {
                arguments.get(1).copied()
            } else {
                arguments.first().copied()
            }
        }
        _ => None,
    }
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

    fn call(output: u32, target: &str, arguments: Vec<ValueId>, line: usize) -> Instruction {
        Instruction::Call {
            output: ValueId(output),
            target: target.to_string(),
            call_kind: CallKind::Function,
            arguments,
            location: location(line),
        }
    }

    fn output(output_kind: OutputKind, values: Vec<ValueId>, line: usize) -> Instruction {
        Instruction::Output {
            output: None,
            output_kind,
            values,
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

    fn literal(output: u32, value: &str, line: usize) -> Instruction {
        Instruction::Literal {
            output: ValueId(output),
            value: LiteralValue::String(value.to_string()),
            location: location(line),
        }
    }

    fn function_start(name: &str, parameters: &[&str], line: usize) -> Instruction {
        Instruction::FunctionStart {
            name: name.to_string(),
            parameters: parameters.iter().map(|value| (*value).to_string()).collect(),
            location: location(line),
        }
    }

    fn function_end(name: &str, line: usize) -> Instruction {
        Instruction::FunctionEnd {
            name: name.to_string(),
            location: location(line),
        }
    }

    #[test]
    fn reports_tainted_command_with_dataflow() {
        let mut instructions = tainted_input("$_GET");
        instructions.push(call(2, "system", vec![ValueId(1)], 2));
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
    fn reports_tainted_sql_query() {
        let mut instructions = tainted_input("$_POST");
        instructions.push(literal(2, "'connection'", 2));
        instructions.push(call(
            3,
            "mysqli_query",
            vec![ValueId(2), ValueId(1)],
            3,
        ));
        let module = ModuleIr {
            language: "php".to_string(),
            path: "src/example.php".to_string(),
            instructions,
        };
        let findings = TaintedSqlRule.evaluate(&ModuleAnalysis::new(&module));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].cwe.as_deref(), Some("CWE-89"));
    }

    #[test]
    fn reports_tainted_echo_as_reflected_xss() {
        let mut instructions = tainted_input("$_GET");
        instructions.push(output(OutputKind::Echo, vec![ValueId(1)], 2));
        let module = ModuleIr {
            language: "php".to_string(),
            path: "src/example.php".to_string(),
            instructions,
        };
        let findings = TaintedHtmlOutputRule.evaluate(&ModuleAnalysis::new(&module));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].cwe.as_deref(), Some("CWE-79"));
        assert!(findings[0]
            .dataflow
            .iter()
            .any(|step| step.label.contains("echo")));
    }

    #[test]
    fn reports_one_finding_for_multi_value_echo() {
        let mut instructions = tainted_input("$_GET");
        instructions.push(Instruction::VariableRead {
            output: ValueId(2),
            name: "$_POST".to_string(),
            location: location(2),
        });
        instructions.push(output(
            OutputKind::Echo,
            vec![ValueId(1), ValueId(2)],
            3,
        ));
        let module = ModuleIr {
            language: "php".to_string(),
            path: "src/example.php".to_string(),
            instructions,
        };
        assert_eq!(
            TaintedHtmlOutputRule
                .evaluate(&ModuleAnalysis::new(&module))
                .len(),
            1
        );
    }

    #[test]
    fn html_encoding_suppresses_only_xss() {
        let mut instructions = tainted_input("$_REQUEST");
        instructions.push(call(2, "htmlspecialchars", vec![ValueId(1)], 2));
        instructions.push(output(OutputKind::Print, vec![ValueId(2)], 3));
        instructions.push(call(3, "system", vec![ValueId(2)], 4));
        instructions.push(call(4, "mysql_query", vec![ValueId(2)], 5));
        let module = ModuleIr {
            language: "php".to_string(),
            path: "src/example.php".to_string(),
            instructions,
        };
        let analysis = ModuleAnalysis::new(&module);
        assert!(TaintedHtmlOutputRule.evaluate(&analysis).is_empty());
        assert_eq!(TaintedCommandRule.evaluate(&analysis).len(), 1);
        assert_eq!(TaintedSqlRule.evaluate(&analysis).len(), 1);
    }

    #[test]
    fn shell_sanitizer_does_not_hide_xss() {
        let mut instructions = tainted_input("$_GET");
        instructions.push(call(2, "escapeshellarg", vec![ValueId(1)], 2));
        instructions.push(output(OutputKind::Echo, vec![ValueId(2)], 3));
        let module = ModuleIr {
            language: "php".to_string(),
            path: "src/example.php".to_string(),
            instructions,
        };
        assert_eq!(
            TaintedHtmlOutputRule
                .evaluate(&ModuleAnalysis::new(&module))
                .len(),
            1
        );
    }

    #[test]
    fn propagates_xss_through_function_return_summary() {
        let mut instructions = vec![
            function_start("passthrough", &["$value"], 1),
            Instruction::VariableRead {
                output: ValueId(10),
                name: "$value".to_string(),
                location: location(2),
            },
            Instruction::Return {
                value: Some(ValueId(10)),
                location: location(2),
            },
            function_end("passthrough", 3),
        ];
        instructions.extend(tainted_input("$_GET"));
        instructions.push(call(2, "passthrough", vec![ValueId(1)], 5));
        instructions.push(output(OutputKind::Echo, vec![ValueId(2)], 6));
        let module = ModuleIr {
            language: "php".to_string(),
            path: "src/example.php".to_string(),
            instructions,
        };
        let findings = TaintedHtmlOutputRule.evaluate(&ModuleAnalysis::new(&module));
        assert_eq!(findings.len(), 1);
        assert!(findings[0]
            .dataflow
            .iter()
            .any(|step| step.label.contains("passthrough")));
    }

    #[test]
    fn html_sanitizer_summary_is_domain_specific() {
        let mut instructions = vec![
            function_start("safe_html", &["$value"], 1),
            Instruction::VariableRead {
                output: ValueId(10),
                name: "$value".to_string(),
                location: location(2),
            },
            call(11, "htmlentities", vec![ValueId(10)], 2),
            Instruction::Return {
                value: Some(ValueId(11)),
                location: location(2),
            },
            function_end("safe_html", 3),
        ];
        instructions.extend(tainted_input("$_GET"));
        instructions.push(call(2, "safe_html", vec![ValueId(1)], 4));
        instructions.push(output(OutputKind::Echo, vec![ValueId(2)], 5));
        instructions.push(call(3, "system", vec![ValueId(2)], 6));
        let module = ModuleIr {
            language: "php".to_string(),
            path: "src/example.php".to_string(),
            instructions,
        };
        let analysis = ModuleAnalysis::new(&module);
        assert!(TaintedHtmlOutputRule.evaluate(&analysis).is_empty());
        assert_eq!(TaintedCommandRule.evaluate(&analysis).len(), 1);
    }

    #[test]
    fn constant_output_is_not_tainted() {
        let module = ModuleIr {
            language: "php".to_string(),
            path: "src/example.php".to_string(),
            instructions: vec![
                literal(0, "'hello'", 1),
                output(OutputKind::Echo, vec![ValueId(0)], 1),
            ],
        };
        assert!(TaintedHtmlOutputRule
            .evaluate(&ModuleAnalysis::new(&module))
            .is_empty());
    }

    #[test]
    fn print_result_does_not_inherit_printed_taint() {
        let mut instructions = tainted_input("$_GET");
        instructions.push(Instruction::Output {
            output: Some(ValueId(2)),
            output_kind: OutputKind::Print,
            values: vec![ValueId(1)],
            location: location(2),
        });
        instructions.push(call(3, "system", vec![ValueId(2)], 3));
        let module = ModuleIr {
            language: "php".to_string(),
            path: "src/example.php".to_string(),
            instructions,
        };
        let analysis = ModuleAnalysis::new(&module);
        assert_eq!(TaintedHtmlOutputRule.evaluate(&analysis).len(), 1);
        assert!(TaintedCommandRule.evaluate(&analysis).is_empty());
    }

    #[test]
    fn resolves_repeated_constant_operands() {
        let module = ModuleIr {
            language: "php".to_string(),
            path: "src/example.php".to_string(),
            instructions: vec![
                literal(0, "'a'", 1),
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

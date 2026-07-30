use serde_json::Value;
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_fermio-sec")
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/e2e")
        .join(name)
}

fn run_scan(path: &Path, additional_arguments: &[&str]) -> Output {
    let mut command = Command::new(binary());
    command.arg("scan").arg(path).arg("--format").arg("json");
    command.args(additional_arguments);
    command.output().expect("fermio-sec should execute")
}

fn scan_json(path: &Path, additional_arguments: &[&str]) -> Value {
    let output = run_scan(path, additional_arguments);
    assert!(
        output.status.success(),
        "scan failed with status {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("scan should emit valid JSON")
}

fn fixture_json(name: &str) -> Value {
    scan_json(&fixture(name), &[])
}

fn rule_ids(report: &Value) -> BTreeSet<String> {
    report["findings"]
        .as_array()
        .expect("findings should be an array")
        .iter()
        .filter_map(|finding| finding["rule_id"].as_str().map(str::to_string))
        .collect()
}

fn frameworks(report: &Value) -> BTreeSet<String> {
    report["project"]["frameworks"]
        .as_array()
        .expect("frameworks should be an array")
        .iter()
        .filter_map(|framework| framework.as_str().map(str::to_string))
        .collect()
}

#[test]
fn scans_framework_profiles_end_to_end() {
    let cases = [
        (
            "laravel",
            "laravel",
            ["FERMIO-LARAVEL-DEBUG-DD-001", "FERMIO-LARAVEL-DB-RAW-001"],
        ),
        (
            "symfony",
            "symfony",
            [
                "FERMIO-SYMFONY-DEBUG-DUMP-001",
                "FERMIO-SYMFONY-PROCESS-SHELL-001",
            ],
        ),
        (
            "wordpress",
            "wordpress",
            [
                "FERMIO-WORDPRESS-AJAX-NOPRIV-001",
                "FERMIO-WORDPRESS-DEBUG-LOG-001",
            ],
        ),
    ];

    for (fixture_name, framework, expected_rules) in cases {
        let report = fixture_json(fixture_name);
        let detected_frameworks = frameworks(&report);
        let detected_rules = rule_ids(&report);
        assert!(
            detected_frameworks.contains(framework),
            "{fixture_name} should be detected as {framework}"
        );
        for rule in expected_rules {
            assert!(
                detected_rules.contains(rule),
                "{fixture_name} should emit {rule}; actual rules: {detected_rules:?}"
            );
        }
    }
}

#[test]
fn detects_representative_taint_findings() {
    let report = fixture_json("vulnerable");
    let rules = rule_ids(&report);
    for expected in [
        "FERMIO-PHP-TAINT-CMD-001",
        "FERMIO-PHP-TAINT-SQL-OO-001",
        "FERMIO-PHP-TAINT-XSS-001",
    ] {
        assert!(
            rules.contains(expected),
            "vulnerable fixture should emit {expected}; actual rules: {rules:?}"
        );
    }
}

#[test]
fn keeps_safe_fixture_free_of_findings() {
    let report = fixture_json("safe");
    assert_eq!(
        report["statistics"]["findings"].as_u64(),
        Some(0),
        "safe fixture findings: {:?}",
        report["findings"]
    );
}

#[test]
fn loads_external_rulepack_from_project_configuration() {
    let report = fixture_json("custom-rulepack");
    assert!(rule_ids(&report).contains("FERMIO-ACME-DEBUG-001"));
}

#[test]
fn fails_closed_when_file_count_limit_is_exceeded() {
    let output = run_scan(&fixture("limits"), &["--max-files", "1"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("exceeding the configured limit"));
}

#[test]
fn reports_files_skipped_by_size_limit() {
    let report = scan_json(&fixture("limits"), &["--max-file-size", "8"]);
    assert_eq!(report["statistics"]["files_skipped"].as_u64(), Some(2));
    assert!(report["diagnostics"]
        .as_array()
        .expect("diagnostics should be an array")
        .iter()
        .all(|diagnostic| diagnostic["code"] == "SCAN-LIMIT-001"));
}

#[test]
fn scans_small_project_corpus_within_release_budget() {
    let project = TemporaryProject::new();
    for index in 0..250 {
        fs::write(
            project.path().join(format!("file-{index:03}.php")),
            "<?php\n$value = 'safe';\necho htmlspecialchars($value, ENT_QUOTES, 'UTF-8');\n",
        )
        .expect("fixture file should be written");
    }

    let started = Instant::now();
    let report = scan_json(project.path(), &["--no-config"]);
    let elapsed = started.elapsed();

    assert_eq!(report["statistics"]["files_parsed"].as_u64(), Some(250));
    assert!(
        elapsed < Duration::from_secs(30),
        "250-file release corpus exceeded the 30 second budget: {elapsed:?}"
    );
}

struct TemporaryProject {
    path: PathBuf,
}

impl TemporaryProject {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "fermio-release-e2e-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("temporary project should be created");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryProject {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

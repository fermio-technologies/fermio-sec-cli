use anyhow::{bail, Context, Result};
use fermio_core::Severity;
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

pub const CONFIG_FILE_NAME: &str = ".fermio.toml";
pub const CONFIG_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FermioConfig {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub scan: ScanConfig,
    pub rules: RulesConfig,
}

impl Default for FermioConfig {
    fn default() -> Self {
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            scan: ScanConfig::default(),
            rules: RulesConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanConfig {
    pub include_vendor: Option<bool>,
    pub max_files: Option<usize>,
    pub max_file_size: Option<u64>,
    pub fail_on: Option<Severity>,
    pub baseline: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RulesConfig {
    pub enabled: Option<Vec<String>>,
    pub disabled: Vec<String>,
    pub severity: BTreeMap<String, Severity>,
}

#[derive(Debug, Clone)]
pub struct LoadedConfig {
    pub config: FermioConfig,
    pub path: Option<PathBuf>,
}

impl LoadedConfig {
    pub fn resolve_path(&self, value: &Path) -> PathBuf {
        if value.is_absolute() {
            return value.to_path_buf();
        }

        self.path
            .as_deref()
            .and_then(Path::parent)
            .unwrap_or_else(|| Path::new("."))
            .join(value)
    }
}

pub fn load_for_root(
    root: &Path,
    explicit_path: Option<&Path>,
    disabled: bool,
) -> Result<LoadedConfig> {
    if disabled {
        return Ok(LoadedConfig {
            config: FermioConfig::default(),
            path: None,
        });
    }

    let path = explicit_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| root.join(CONFIG_FILE_NAME));

    if !path.is_file() {
        if explicit_path.is_some() {
            bail!("configuration file does not exist: {}", path.display());
        }
        return Ok(LoadedConfig {
            config: FermioConfig::default(),
            path: None,
        });
    }

    let content = fs::read_to_string(&path)
        .with_context(|| format!("failed to read configuration {}", path.display()))?;
    let config = parse(&content)
        .with_context(|| format!("invalid Fermio configuration in {}", path.display()))?;

    Ok(LoadedConfig {
        config,
        path: Some(path),
    })
}

pub fn parse(content: &str) -> Result<FermioConfig> {
    let config: FermioConfig = toml::from_str(content).context("invalid TOML")?;
    validate(&config)?;
    Ok(config)
}

fn validate(config: &FermioConfig) -> Result<()> {
    if config.schema_version != CONFIG_SCHEMA_VERSION {
        bail!(
            "unsupported configuration schema version {}; expected {}",
            config.schema_version,
            CONFIG_SCHEMA_VERSION
        );
    }

    if config.scan.max_files == Some(0) {
        bail!("scan.max_files must be greater than zero");
    }
    if config.scan.max_file_size == Some(0) {
        bail!("scan.max_file_size must be greater than zero");
    }

    if let Some(enabled) = &config.rules.enabled {
        validate_rule_list("rules.enabled", enabled)?;
    }
    validate_rule_list("rules.disabled", &config.rules.disabled)?;

    let enabled = config
        .rules
        .enabled
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for rule_id in &config.rules.disabled {
        if enabled.contains(rule_id.as_str()) {
            bail!("rule `{rule_id}` cannot be both enabled and disabled");
        }
    }

    for rule_id in config.rules.severity.keys() {
        if rule_id.trim().is_empty() {
            bail!("rules.severity contains an empty rule identifier");
        }
    }

    Ok(())
}

fn validate_rule_list(name: &str, values: &[String]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        if value.trim().is_empty() {
            bail!("{name} contains an empty rule identifier");
        }
        if !seen.insert(value.as_str()) {
            bail!("{name} contains duplicate rule `{value}`");
        }
    }
    Ok(())
}

const fn default_schema_version() -> u32 {
    CONFIG_SCHEMA_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_scan_and_rule_configuration() {
        let config = parse(
            r#"
                schema_version = 1

                [scan]
                include_vendor = true
                max_files = 25000
                max_file_size = 1048576
                fail_on = "high"
                baseline = ".fermio-baseline.json"

                [rules]
                enabled = ["RULE-A", "RULE-B"]
                disabled = ["RULE-B-LEGACY"]

                [rules.severity]
                RULE-A = "critical"
            "#,
        )
        .expect("configuration should parse");

        assert_eq!(config.scan.include_vendor, Some(true));
        assert_eq!(config.scan.max_files, Some(25_000));
        assert_eq!(config.scan.fail_on, Some(Severity::High));
        assert_eq!(
            config.rules.severity.get("RULE-A"),
            Some(&Severity::Critical)
        );
    }

    #[test]
    fn rejects_unknown_fields() {
        let error = parse("schema_version = 1\nunknown = true")
            .expect_err("unknown fields must be rejected");
        assert!(error.to_string().contains("invalid TOML"));
    }

    #[test]
    fn rejects_unsupported_schema_versions() {
        let error = parse("schema_version = 2")
            .expect_err("unsupported schema versions must fail");
        assert!(error.to_string().contains("unsupported configuration schema"));
    }

    #[test]
    fn rejects_conflicting_rule_selection() {
        let error = parse(
            r#"
                [rules]
                enabled = ["RULE-A"]
                disabled = ["RULE-A"]
            "#,
        )
        .expect_err("conflicting selection must fail");
        assert!(error.to_string().contains("both enabled and disabled"));
    }

    #[test]
    fn resolves_relative_paths_from_configuration_directory() {
        let loaded = LoadedConfig {
            config: FermioConfig::default(),
            path: Some(PathBuf::from("config/security/.fermio.toml")),
        };
        assert_eq!(
            loaded.resolve_path(Path::new("baseline.json")),
            PathBuf::from("config/security/baseline.json")
        );
    }
}

# Configuration

!!! info "What this page covers"
    Versioned `.fermio.toml` schema, path resolution, rule selection and fail-closed configuration errors.

## Where config is read

1. If `--config <FILE>` is passed, that file is used.
2. Otherwise, if `.fermio.toml` exists at the scan root, it is loaded.
3. `--no-config` disables loading.

Unknown fields, unsupported `schema_version`, invalid limits, conflicting rule selection, duplicate rulepacks or unknown IDs **stop** the scan with exit code `2`.

## Example

```toml
schema_version = 1

[scan]
include_vendor = false
max_files = 100000
max_file_size = 2097152
fail_on = "high"
baseline = ".fermio-baseline.json"

[rules]
enabled = [
  "FERMIO-PHP-TAINT-SQL-001",
  "FERMIO-PHP-TAINT-SQL-OO-001",
  "FERMIO-WORDPRESS-AJAX-NOPRIV-001",
]
disabled = []

[rules.severity]
"FERMIO-PHP-TAINT-SQL-OO-001" = "critical"

[rulepacks]
builtins = true
paths = ["security/company-rulepack.toml"]
```

See [`fermio.example.toml`](https://github.com/fermio-technologies/fermio-sec-cli/blob/main/fermio.example.toml) for a complete starter.

## Path resolution

Paths in `scan.baseline` and `rulepacks.paths` resolve **relative to the configuration file directory**, not the process CWD.

## Rule selection

| Field | Effect |
|---|---|
| `rules.enabled` | when present, only those rules (minus `disabled`) |
| `rules.disabled` | removes rules from the selection |
| `rules.severity` | per-ID severity override |

!!! warning "enabled/disabled conflict"
    The same ID in both lists is a configuration error (fail-closed).

External rulepack IDs may appear in `enabled` / `disabled` / `severity` because packs load **before** rule validation.

## Rulepacks in config

```toml
[rulepacks]
builtins = true
paths = ["security/company-rulepack.toml"]
```

Details: [Rulepacks](rulepacks.md).

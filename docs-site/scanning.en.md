# Scanning

!!! info "What this page covers"
    How to run `fermio-sec scan`, output formats, resource limits, ignores and fail-on severity behavior.

## Basic command

```bash
fermio-sec scan [PATH]
```

Default `PATH`: `.` (current directory).

## Output formats

| Value | Use |
|---|---|
| `terminal` (default) | human-readable stdout report |
| `json` | structured report |
| `sarif` | SARIF 2.1.0 (Code Scanning / viewers) |

```bash
fermio-sec scan . --format json
fermio-sec scan . --format sarif --output fermio.sarif
```

`--output` writes the report to the given file. Without it, output goes to stdout.

## Resource limits

| Flag / config | Default | Behavior |
|---|---|---|
| `--max-files` / `scan.max_files` | `100000` | exceeding the limit **stops** the scan (exit `2`) |
| `--max-file-size` / `scan.max_file_size` | `2097152` (2 MiB) | oversized files are **skipped** with diagnostic `SCAN-LIMIT-001` |

```bash
fermio-sec scan . --max-files 50000 --max-file-size 1048576
```

## Vendor and ignores

By default `vendor/` is excluded. Force inclusion with:

```bash
fermio-sec scan . --include-vendor
```

Create `.fermioignore` at the project root (gitignore-style syntax):

```gitignore
storage/**
cache/**
generated/**
```

The scanner also respects `.gitignore`.

## Fail on severity

```bash
fermio-sec scan . --fail-on high
```

Values: `low`, `medium`, `high`, `critical`. The scan fails when a finding at or above the threshold remains (after baseline, if any).

Severity overrides in `.fermio.toml` affect the report and failure threshold, but **do not** change fingerprints or baseline compatibility.

## CLI vs config precedence

1. Explicit CLI flags
2. Values from `.fermio.toml` (or `--config`)
3. Built-in defaults

`--no-config` disables project configuration loading.

## Inventory helpers

```bash
fermio-sec languages
fermio-sec frameworks
fermio-sec rules
```

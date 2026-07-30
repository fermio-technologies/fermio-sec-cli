# fermio-sec-cli

`fermio-sec-cli` is the local-first static analysis CLI from Fermio Technologies.

The first release targets PHP and its main ecosystems. The core architecture remains language-neutral so future frontends can be added without rewriting the analysis engine.

## Initial scope

- Generic PHP projects
- Composer project discovery
- Laravel, Symfony and WordPress detection
- PHP parsing through Tree-sitter
- Structured syntax diagnostics
- Deterministic rule execution
- Terminal, JSON and SARIF 2.1.0 reports
- Stable SHA-256 finding fingerprints
- Local fingerprint baselines
- Versioned `.fermio.toml` configuration
- Strict local declarative rulepacks
- Framework-aware Laravel, Symfony and WordPress semantic profiles
- PHP command, SQL and reflected-XSS taint analysis
- Receiver-aware PDO and MySQLi SQL taint analysis
- Limited same-file function return and sink summaries
- SARIF code-flow traces for taint findings
- `.gitignore` and `.fermioignore` support
- File-count and file-size scan limits
- Local-only scans by default

## Installation

Tagged releases publish archives for Linux x86_64, Windows x86_64, macOS Intel and macOS Apple Silicon. Every archive includes a SHA-256 checksum, installation instructions, the changelog and the AGPL-3.0 license.

See [`INSTALL.md`](INSTALL.md) for checksum verification, binary installation and source-build instructions.

## Commands

```bash
cargo run -p fermio-cli -- scan .
cargo run -p fermio-cli -- scan . --format json
cargo run -p fermio-cli -- scan . --format sarif --output fermio.sarif
cargo run -p fermio-cli -- scan . --max-files 50000 --max-file-size 2097152
cargo run -p fermio-cli -- scan . --config config/security.toml
cargo run -p fermio-cli -- scan . --no-config
cargo run -p fermio-cli -- languages
cargo run -p fermio-cli -- frameworks
cargo run -p fermio-cli -- rules
```

## Configuration

Fermio automatically reads `.fermio.toml` from the scan root when the file exists. Use `--config <FILE>` to select another file or `--no-config` to disable configuration loading. An explicitly supplied CLI value takes precedence over the corresponding configured value.

Configuration uses a versioned and strictly validated schema. Unknown fields, unsupported schema versions, invalid limits, conflicting rule selections, duplicate rulepack paths and unknown rule identifiers stop the scan with exit code `2`.

```toml
schema_version = 1

[scan]
include_vendor = false
max_files = 100000
max_file_size = 2097152
fail_on = "high"
baseline = ".fermio-baseline.json"

[rules]
# Omit `enabled` to run every registered rule.
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

Paths declared in the configuration, including `scan.baseline` and `rulepacks.paths`, are resolved relative to the configuration file. Rule severity overrides affect reports and the configured or command-line failure threshold, but do not change stable fingerprints or baseline compatibility. See [`fermio.example.toml`](fermio.example.toml) for a complete starting point.

## Declarative rulepacks

Rulepacks are local TOML files with a versioned, closed schema. The first schema supports deterministic call rules with:

- rule metadata, severity, confidence and optional CWE;
- exact normalized call targets;
- function, method, nullsafe-method, static-method or dynamic-call filters;
- optional literal-string equality or prefix matching on one argument;
- optional activation only when one of the declared frameworks is detected.

Rulepacks cannot execute scripts, load dynamic libraries, use arbitrary regular expressions or request network access. Each file is limited to 1 MiB and 1,000 rules. Unknown fields, duplicate IDs, malformed CWE identifiers and invalid argument matchers fail closed.

Example external rulepack:

```toml
schema_version = 1
id = "acme.php.policy"
version = "1.0.0"

[[rules]]
id = "FERMIO-ACME-DEBUG-001"
title = "Application debug helper"
description = "Remove the organization debug helper from production code."
severity = "medium"
confidence = "high"
cwe = "CWE-489"
targets = ["acme_debug"]
call_kinds = ["function"]
```

The built-in framework rulepack currently includes:

- Laravel `dd()` and static `raw()` database-expression review;
- Symfony `dump()` and `Process::fromShellCommandline()` review;
- WordPress unauthenticated `wp_ajax_nopriv_` registrations and direct `error_log()` review.

Framework-restricted rules remain registered for configuration validation but emit findings only when their framework is detected. The initial static-method matcher records the method name rather than performing full class-resolution, so rules such as Laravel `raw()` intentionally use medium confidence.

## Command taint analysis

The command source-to-sink analysis follows PHP superglobal input through indexed reads, assignments, variable reads and string concatenation into command execution functions such as `system`, `exec` and `shell_exec`.

The functions `escapeshellarg()` and `escapeshellcmd()` are recognized as command sanitizers. A value sanitized for command use remains tainted for unrelated domains such as SQL and HTML output.

## SQL taint analysis

The procedural SQL analysis reports `FERMIO-PHP-TAINT-SQL-001` when PHP superglobal input reaches a supported procedural query API at its SQL argument position.

The initial procedural sink set includes:

- `mysql_query`
- `mysqli_query`, `mysqli_multi_query`, `mysqli_real_query` and `mysqli_execute_query`
- `pg_query`, `pg_send_query`, `pg_query_params`, `pg_send_query_params` and `pg_prepare`
- `odbc_exec`
- `sqlsrv_query` and `sqlsrv_prepare`

The initial SQL sanitizer set includes `mysql_real_escape_string`, the procedural MySQLi escape functions, and PostgreSQL string, literal and identifier escaping functions. Sanitization is domain-specific: SQL escaping does not suppress command-injection or reflected-XSS findings.

Prepared statements are not treated as safe merely because a function is named `prepare`; tainted SQL structure passed to `pg_prepare` or `sqlsrv_prepare` is still reported. Parameter values passed separately to parameterized APIs are outside the SQL-text argument and are not classified as query structure.

### Receiver-aware PDO and MySQLi analysis

`FERMIO-PHP-TAINT-SQL-OO-001` covers object-oriented database calls when the frontend can prove that the receiver originated from `new PDO`, `new mysqli`, a direct alias of such a variable, or an inline object creation.

The initial object sink set includes:

- `PDO::query`, `PDO::exec` and `PDO::prepare`
- `mysqli::query`, `mysqli::real_query`, `mysqli::multi_query`, `mysqli::execute_query` and `mysqli::prepare`

`PDO::quote`, `mysqli::real_escape_string` and `mysqli::escape_string` are recognized as SQL sanitizers for this rule. Procedural SQL sanitizers also remain effective when their result reaches an object sink. Shell and HTML escaping remain tainted for SQL use.

The receiver proof is intentionally conservative. Generic calls such as `$service->query($sql)` are ignored. Reassigning a proven database variable to an unknown expression clears its inferred type. Namespaced user classes such as `App\PDO` are not treated as the native `PDO` class. Import aliases, dependency-injection containers, typed properties, method return types and cross-file type resolution are deferred.

## Reflected XSS analysis

The reflected-XSS analysis reports `FERMIO-PHP-TAINT-XSS-001` when PHP superglobal input reaches an `echo` or `print` output instruction without recognized HTML encoding.

The initial HTML sanitizer set contains `htmlspecialchars()` and `htmlentities()`. Encoding is tracked only for the HTML domain: it does not suppress SQL or command-injection findings, and shell or SQL escaping does not suppress XSS findings.

`echo` can contain multiple expressions, but Fermio emits at most one finding for each output statement. `print` is modeled as an output sink that returns an independent result value, so the printed input does not taint variables assigned from the return value of `print`.

This first slice models direct PHP output as an HTML response context. It does not yet distinguish HTML text, attribute, JavaScript, CSS or URL subcontexts, nor does it model template engines or framework response objects.

## Limited function summaries

Named, same-file PHP functions receive both return summaries and sink summaries. Taint and domain-specific sanitizer state can cross a helper return, while tainted arguments passed into helpers can be followed to command, procedural SQL and HTML sinks inside those helpers.

Return summaries support flows such as:

```php
function passthrough($value) {
    return $value;
}

echo passthrough($_GET['name']);
```

Sink summaries support flows where the dangerous operation is hidden behind an application helper:

```php
function run_command($command) {
    system($command);
}

run_command($_GET['cmd']);
```

The finding is anchored at the tainted helper call and the redacted trace continues through the parameter read to the internal sink. Sink summaries preserve argument positions, so connection handles are not mistaken for SQL text in wrappers around APIs such as `mysqli_query()`.

Summaries are calculated to a bounded fixed point, allowing short chains of named helper calls. Sanitization can occur before entering a helper or inside it and remains specific to command, SQL or HTML use. Functions that directly return or sink superglobal input are also analyzed. Local assignments remain isolated by function scope.

Function summaries do not yet model method bodies, closures, anonymous functions, namespaces across files, omitted default arguments, recursive behavior, references or variadic argument expansion. Object SQL analysis currently covers direct receiver-proven calls rather than method or service-container call graphs.

SARIF output includes redacted `codeFlows` showing structural steps such as the input source, propagation operations, helper calls, helper returns and the sink. The trace does not contain runtime values or source snippets.

## Baseline workflow

Create a baseline from the current findings:

```bash
cargo run -p fermio-cli -- scan . --write-baseline .fermio-baseline.json
```

Use that baseline in CI so only new findings remain in the report and affect `--fail-on`:

```bash
cargo run -p fermio-cli -- scan . \
  --baseline .fermio-baseline.json \
  --format sarif \
  --output fermio.sarif \
  --fail-on high
```

The baseline contains only stable finding fingerprints. It does not contain source code, evidence snippets or secret values. Baseline schema versions are validated before use.

Create a `.fermioignore` file in the project root to exclude generated or application-specific paths:

```gitignore
storage/**
cache/**
generated/**
```

Default scan limits are 100,000 PHP files and 2 MiB per file. Oversized files are skipped with a diagnostic; exceeding the total file-count limit stops the scan.

## Release validation

The CI release gate covers formatting, Clippy, unit and documentation tests, framework and taint fixtures, external rulepack loading, resource-limit regressions, and a 250-file performance smoke test. Tagged releases package four supported targets and publish SHA-256 checksums plus the dependency lockfile used by every build.

## License

`fermio-sec-cli` is licensed under the [GNU Affero General Public License v3.0 only](LICENSE) (`AGPL-3.0-only`).

See [`CHANGELOG.md`](CHANGELOG.md), [`SECURITY.md`](SECURITY.md), [`docs/RELEASE.md`](docs/RELEASE.md), [`docs/DESIGN-v0.1.md`](docs/DESIGN-v0.1.md) and [`docs/ROADMAP.md`](docs/ROADMAP.md).

# Fermio Sec CLI — Design v0.1

## 1. Purpose

`fermio-sec-cli` is a local-first Static Application Security Testing CLI written in Rust. Version 0.1 introduces PHP support while preserving a language-neutral engine boundary for future frontends.

The scanner must work without a backend. Cloud synchronization is an optional future capability and must never be required for the security decision itself.

## 2. Product boundaries

### In scope

- Scan local PHP source trees.
- Detect generic PHP, Composer, Laravel, Symfony and WordPress projects.
- Parse PHP files without executing application code.
- Run deterministic syntax and API-usage rules.
- Produce terminal and JSON findings.
- Return CI-compatible exit codes.
- Preserve source locations and stable fingerprints.
- Define language and framework extension contracts.

### Out of scope for v0.1

- Full interprocedural taint analysis.
- Complete PHP type inference.
- Runtime instrumentation.
- Automatic source-code fixes.
- Uploading source code.
- Mandatory authentication or backend access.
- Go, Rust, Dart or other language frontends.

## 3. Architectural principles

1. **Local-first:** scanning and decisions occur on the developer machine or CI runner.
2. **Deterministic core:** findings must be reproducible from source, configuration and rulepack version.
3. **Language-neutral engine:** PHP-specific syntax stays behind the language frontend.
4. **No project execution:** never run Composer scripts, PHP files or application bootstrap code.
5. **Frameworks are semantic profiles:** Laravel, Symfony and WordPress reuse the PHP parser.
6. **Privacy by default:** the initial version has no network requirement.
7. **Evidence-oriented findings:** every finding contains rule, severity, location and fingerprint.

## 4. High-level flow

```text
CLI command
  -> configuration
  -> project discovery
  -> file discovery
  -> language frontend selection
  -> PHP parsing
  -> PHP syntax model
  -> Fermio IR
  -> rules
  -> findings
  -> terminal or JSON report
```

## 5. Workspace

```text
fermio-sec-cli/
  crates/
    fermio-cli/           Command-line interface
    fermio-core/          Shared domain types
    fermio-engine/        Scan orchestration
    fermio-language-api/  Language frontend contract
    fermio-language-php/  PHP parser and project detection
    fermio-ir/            Language-neutral intermediate representation
    fermio-rules/         Rule contract and built-in rules
    fermio-report/        Terminal and JSON output
  rulepacks/php/           Future declarative rulepacks
  tests/fixtures/php/      Vulnerable and safe PHP fixtures
```

## 6. Core domain model

A scan request identifies the project root, output format and failure threshold. A scan result contains project metadata, diagnostics, statistics and findings.

A finding contains:

- unique rule identifier;
- title and description;
- severity and confidence;
- relative path and source range;
- optional code evidence;
- stable fingerprint;
- CWE metadata when available;
- framework metadata when applicable.

## 7. PHP frontend

The PHP frontend is responsible for:

- matching `.php` files;
- parsing with Tree-sitter PHP;
- returning parser diagnostics;
- reading `composer.json` without executing Composer;
- detecting Laravel, Symfony and WordPress using package and filesystem evidence;
- lowering relevant syntax to the Fermio IR.

The rest of the engine must not depend directly on `tree_sitter::Node`.

## 8. Framework detection

### Laravel

Evidence includes `laravel/framework` in Composer dependencies, `artisan`, `bootstrap/app.php`, `routes/` and `app/Http/`.

### Symfony

Evidence includes `symfony/framework-bundle`, `bin/console`, `config/bundles.php` and `src/Kernel.php`.

### WordPress

Evidence includes `wp-includes/version.php`, `wp-config.php`, `wp-content/plugins/` or `wp-content/themes/`.

Detection is additive: more than one ecosystem profile may be active.

## 9. Initial rule families

The bootstrap implementation establishes the rule API and provides representative checks:

- `FERMIO-PHP-CORE-EVAL-001`: use of `eval`;
- `FERMIO-PHP-CORE-CMD-001`: direct command-execution functions;
- `FERMIO-PHP-CORE-DESERIALIZE-001`: use of `unserialize`;
- `FERMIO-PHP-CORE-CRYPTO-001`: weak hash APIs;
- `FERMIO-PHP-CORE-SECRET-001`: likely hard-coded secrets.

These checks are intentionally syntax-oriented. They validate the end-to-end architecture before deeper dataflow is introduced.

## 10. Intermediate representation

The first IR is deliberately small:

- modules;
- functions;
- calls;
- assignments;
- literals;
- variable reads;
- returns;
- source locations.

The IR must support later addition of control-flow blocks, call graphs, sources, sinks, sanitizers and taint facts without breaking the language frontend contract.

## 11. CLI contract

```text
fermio-sec scan [PATH]
fermio-sec languages
fermio-sec frameworks
fermio-sec rules
```

Initial scan options:

- `--format terminal|json`
- `--output <path>`
- `--fail-on low|medium|high|critical`
- `--include-vendor`

Exit codes:

- `0`: scan completed and threshold was not exceeded;
- `1`: at least one finding met the failure threshold;
- `2`: configuration, parsing or execution failure.

## 12. Reporting

Terminal output prioritizes readability and CI logs. JSON is the stable machine-readable format. SARIF is planned immediately after the result schema stabilizes.

## 13. Backend integration boundary

A future `fermio-cloud-client` may upload metadata and findings after a local scan. It must depend on the scan result schema, not on parser internals.

Expected future flow:

```text
local scan -> local result -> optional upload -> backend -> dashboard
```

Source upload remains disabled by default. Rulepacks downloaded from a backend must be signed, versioned, declarative and validated before use.

## 14. Security requirements for the scanner

- Do not execute repository code.
- Do not follow symbolic links by default.
- Respect `.gitignore` and `.fermioignore`.
- Exclude `vendor/` by default.
- Limit file size and total file count.
- Treat source files, Composer manifests and rulepacks as untrusted input.
- Never print detected secret values in clear text.
- Avoid network access during local scans.

## 15. Delivery criteria for v0.1

Version 0.1 is complete when:

1. the Rust workspace builds on supported platforms;
2. the CLI scans a local PHP project;
3. PHP syntax errors become diagnostics rather than crashes;
4. framework detection is visible in scan output;
5. representative built-in rules emit findings;
6. terminal and JSON output are covered by tests;
7. CI runs formatting, linting and tests;
8. documentation explains architecture and extension points.

## 16. Next increments

- v0.2: SARIF, baseline support and richer rule configuration.
- v0.3: intraprocedural dataflow and taint analysis.
- v0.4: function summaries and limited interprocedural analysis.
- v0.5: optional backend synchronization and dashboard integration.

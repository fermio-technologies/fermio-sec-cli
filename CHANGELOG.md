# Changelog

All notable changes to `fermio-sec-cli` are documented in this file.

## [Unreleased]

### Planned

- release feedback and compatibility fixes discovered after the first release candidate

## [0.1.0-rc.1] - 2026-07-30

### Added

- local-first PHP project scanning without application execution
- Composer, Laravel, Symfony and WordPress project detection
- Tree-sitter PHP parsing with structured diagnostics
- terminal, JSON and SARIF 2.1.0 reports
- stable SHA-256 finding fingerprints and local baselines
- command-injection, procedural SQL-injection and reflected-XSS taint analysis
- limited same-file function return and sink summaries
- receiver-aware PDO and MySQLi SQL analysis
- versioned `.fermio.toml` configuration
- bounded, data-only declarative rulepacks
- Laravel, Symfony and WordPress semantic profiles
- release fixtures covering vulnerable, safe and framework-specific projects
- resource-limit and performance regression coverage
- Linux, Windows and macOS release archives with SHA-256 checksums

### Security

- source code remains local by default
- project code and Composer scripts are never executed
- rulepacks cannot execute scripts, load native plugins or access the network
- source snippets, runtime values and detected secret values are excluded from baselines

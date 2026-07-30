# Fermio Sec CLI roadmap

This roadmap separates the local-first product from optional cloud capabilities.

## Completed foundation

- PHP project detection and Tree-sitter frontend
- language-neutral IR and deterministic built-in rules
- terminal, JSON and SARIF reporting
- stable fingerprints and local baselines
- command, procedural SQL and reflected-XSS taint analysis
- limited same-file return and sink summaries
- receiver-aware PDO and MySQLi SQL analysis

## Current phase: versioned local configuration

Deliver a strictly validated `.fermio.toml` schema for scan limits, baseline selection, CI thresholds, rule selection and severity overrides.

## Remaining local-first phases

### 1. Declarative rulepacks and framework profiles

- validated local rulepack schema
- rule metadata and compatibility versioning
- Laravel, Symfony and WordPress semantic profiles
- signed remote rulepacks remain a future extension; local scans must not require network access

### 2. Release hardening and distribution

- end-to-end fixture projects for vulnerable and safe cases
- performance and resource-limit regression tests
- CLI packaging and release artifacts for supported platforms
- complete extension documentation and reproducible CI validation

After these two phases, the local-first product can be treated as the first release candidate.

## Optional post-MVP phase

### Cloud synchronization and dashboard integration

Upload finding metadata only after local analysis, with source upload disabled by default. Authentication, organization policy and dashboard workflows must remain optional and must not affect the local security decision.

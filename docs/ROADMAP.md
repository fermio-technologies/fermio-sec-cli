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
- versioned and strictly validated `.fermio.toml` configuration

## Current phase: declarative rulepacks and framework profiles

- closed, versioned local TOML rulepack schema
- bounded file size and rule count
- deterministic call-kind and literal-argument matching
- framework-gated Laravel, Symfony and WordPress semantic profiles
- optional local external rulepacks resolved from `.fermio.toml`
- no scripts, native plugins, arbitrary regular expressions or network loading

## Remaining local-first phase

### Release hardening and distribution

- end-to-end fixture projects for vulnerable and safe cases
- performance and resource-limit regression tests
- CLI packaging and release artifacts for supported platforms
- complete extension documentation and reproducible CI validation
- release checklist, changelog and first release-candidate versioning

After the current rulepack phase is merged, one required local-first phase remains before the product can be treated as the first release candidate.

## Optional post-MVP phase

### Cloud synchronization and dashboard integration

Upload finding metadata only after local analysis, with source upload disabled by default. Authentication, organization policy and dashboard workflows must remain optional and must not affect the local security decision. Signed remote rulepacks may be considered in this phase, but local scans must never require network access.

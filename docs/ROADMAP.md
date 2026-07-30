# Fermio Sec CLI roadmap

This roadmap separates the local-first product from optional cloud capabilities.

## Local-first release candidate scope

The required local-first roadmap is complete for `0.1.0-rc.1`:

- PHP project detection and Tree-sitter frontend
- language-neutral IR and deterministic built-in rules
- terminal, JSON and SARIF reporting
- stable fingerprints and local baselines
- command, procedural SQL and reflected-XSS taint analysis
- limited same-file return and sink summaries
- receiver-aware PDO and MySQLi SQL analysis
- versioned and strictly validated `.fermio.toml` configuration
- bounded, data-only declarative rulepacks
- Laravel, Symfony and WordPress semantic profiles
- vulnerable, safe and framework-specific end-to-end fixtures
- file-count, file-size and performance regression coverage
- AGPL-3.0 release licensing and security policy
- Linux, Windows and macOS packaging with SHA-256 checksums
- release checklist, changelog and release-candidate versioning

## Release-candidate validation

The first release candidate still depends on successful execution of the repository CI and tag-release workflows. A release tag must not be created until formatting, Clippy, unit tests, documentation tests, end-to-end tests and packaging validation have completed successfully.

See [`RELEASE.md`](RELEASE.md) for the release gate and publication procedure.

## Optional post-MVP phase

### Cloud synchronization and dashboard integration

Potential future work includes:

- optional authentication and organization policy;
- upload of finding metadata after local analysis;
- dashboards, trend analysis and policy reporting;
- signed remote rulepack distribution;
- cross-project and cross-repository summaries.

Source upload must remain disabled by default. Local scans must never require network access, authentication or cloud availability, and cloud state must not affect the local security decision.

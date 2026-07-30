# Security model

!!! info "What this page covers"
    Scanner trust boundary, what the CLI never does, and release verification practices.

## Trust boundary

Fermio treats as **untrusted input**:

- scanned repositories;
- PHP sources, Composer manifests, configs, ignore files and rulepacks.

## The CLI must not

- execute PHP or Composer scripts;
- follow symbolic links by default;
- load native/executable rulepack plugins;
- require network access for a local scan;
- print detected secret values in clear text;
- store source snippets or runtime values in baselines.

## Rulepacks

Versioned data only. No scripts, no network, no native libraries. See [Rulepacks](rulepacks.md).

## Releases

Official archives ship with SHA-256 checksums. Verify before install ([Getting started](getting-started.md)).

## Reporting vulnerabilities

Use the private channel described in [`SECURITY.md`](https://github.com/fermio-technologies/fermio-sec-cli/blob/main/SECURITY.md). Do not open a public issue with exploitable details.

## License

The project is **AGPL-3.0-only**. Public code with Affero copyleft: network-offered modifications must provide corresponding source under the same license.

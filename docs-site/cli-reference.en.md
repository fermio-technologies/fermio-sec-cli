# CLI reference

!!! info "What this page covers"
    Catalog of real `fermio-sec` commands and flags (v0.1.0-rc.1).

## `fermio-sec`

```text
fermio-sec <COMMAND>
```

| Global option | Description |
|---|---|
| `-h`, `--help` | help |
| `-V`, `--version` | version |

### Commands

| Command | Description |
|---|---|
| `scan` | analyze a project path |
| `languages` | list supported languages |
| `frameworks` | list detectable / known frameworks |
| `rules` | list registered rules |
| `help` | subcommand help |

## `fermio-sec scan`

```text
fermio-sec scan [OPTIONS] [PATH]
```

| Flag / argument | Type | Default | Description |
|---|---|---|---|
| `[PATH]` | path | `.` | scan root |
| `--format <FORMAT>` | enum | `terminal` | `terminal` \| `json` \| `sarif` |
| `--output <OUTPUT>` | path | — | report output file |
| `--fail-on <FAIL_ON>` | enum | — | `low` \| `medium` \| `high` \| `critical` |
| `--include-vendor` | bool | `false` | include `vendor/` |
| `--max-files <N>` | int | config/default | total PHP file limit |
| `--max-file-size <N>` | bytes | config/default | per-file size limit |
| `--config <FILE>` | path | `.fermio.toml` if present | configuration file |
| `--no-config` | bool | `false` | do not load project config |
| `--baseline <FILE>` | path | — | fingerprint baseline |
| `--write-baseline <FILE>` | path | — | write baseline from current scan |

### Exit codes (summary)

| Code | Typical meaning |
|---|---|
| `0` | success (no `--fail-on` failure) |
| `2` | configuration / fail-closed limit error (e.g. `max-files`) |

## `fermio-sec languages`

Lists available language frontends (today: PHP).

## `fermio-sec frameworks`

Lists known frameworks for detection/profiles.

## `fermio-sec rules`

Lists registered rule IDs (core + builtins + loadable packs in the CLI context).

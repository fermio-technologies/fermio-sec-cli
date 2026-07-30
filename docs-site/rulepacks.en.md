# Rulepacks

!!! info "What this page covers"
    Security boundary, TOML schema v1, loading via `.fermio.toml`, and declarative rule examples.

## Security boundary

Rulepacks are **data-only** TOML documents. Schema v1 does **not** allow:

- scripts or executable expressions;
- dynamic/native libraries;
- arbitrary regular expressions;
- network URLs or downloads;
- automatic transforms / autofix;
- access to environment variables or credentials.

Limits: **1 MiB** per file and **1,000** rules. Unknown fields, duplicate IDs and invalid metadata fail with exit `2`.

## Loading

```toml
[rulepacks]
builtins = true
paths = ["security/company-rulepack.toml"]
```

Relative paths resolve from the configuration file directory.

## Document schema

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
frameworks = ["laravel"]
targets = ["acme_debug"]
call_kinds = ["function"]
argument = { index = 0, string_prefix = "debug_", case_sensitive = true }
```

### Pack fields

| Field | Required | Description |
|---|---|---|
| `schema_version` | yes | must be `1` |
| `id` | yes | non-empty pack identifier |
| `version` | yes | compatibility version |
| `rules` | yes | 1–1000 rules |

### Rule fields

| Field | Required | Description |
|---|---|---|
| `id` | yes | starts with `FERMIO-`; uppercase, digits and hyphens |
| `title` / `description` | yes | title and remediation |
| `severity` | yes | `low` \| `medium` \| `high` \| `critical` |
| `confidence` | yes | `low` \| `medium` \| `high` |
| `cwe` | no | `CWE-N` form |
| `frameworks` | no | emit only when a listed framework is detected |
| `targets` | yes | normalized call targets |
| `call_kinds` | no | default `function` |
| `argument` | no | literal matcher for one argument |

### Call kinds

`function`, `method`, `nullsafe_method`, `static_method`, `dynamic`

!!! note "static_method"
    The static-method matcher records the **method name** without full class resolution. Laravel `raw()` rules intentionally use medium confidence.

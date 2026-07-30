# Declarative rulepacks

Fermio rulepacks are local, versioned TOML documents that create deterministic call-site rules without executing project or rulepack code.

## Loading

Rulepacks are configured in `.fermio.toml`:

```toml
[rulepacks]
builtins = true
paths = ["security/company-rulepack.toml"]
```

Relative paths are resolved from the directory containing the configuration file. Built-in framework profiles are enabled by default. Set `builtins = false` to load only compiled core rules and explicitly configured local rulepacks.

Rulepacks are loaded before `rules.enabled`, `rules.disabled` and `rules.severity` are validated. Therefore, IDs from an external rulepack can be selected and overridden through the normal rule configuration.

## Security boundary

Schema version 1 permits data only. It does not support:

- scripts or executable expressions;
- dynamic or native libraries;
- arbitrary regular expressions;
- network URLs or package downloads;
- source transformations or automatic fixes;
- access to environment variables or credentials.

Each file is limited to 1 MiB and 1,000 rules. Duplicate IDs, unknown fields and invalid metadata fail the scan with exit code `2`.

Rule identifiers are interned once for the lifetime of the CLI process because the current rule registry exposes stable string identifiers. The rule count limit bounds this process-lifetime allocation.

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
| --- | --- | --- |
| `schema_version` | yes | Must be `1`. |
| `id` | yes | Non-empty pack identifier. |
| `version` | yes | Non-empty compatibility version. |
| `rules` | yes | One or more rule definitions, up to 1,000. |

### Rule fields

| Field | Required | Description |
| --- | --- | --- |
| `id` | yes | Starts with `FERMIO-`; uppercase letters, digits and hyphens only. |
| `title` | yes | Finding title. |
| `description` | yes | Finding explanation and remediation direction. |
| `severity` | yes | `low`, `medium`, `high` or `critical`. |
| `confidence` | yes | `low`, `medium` or `high`. |
| `cwe` | no | Numeric identifier in `CWE-N` form. |
| `frameworks` | no | Rule emits only when at least one listed framework is detected. |
| `targets` | yes | Exact call targets, normalized case-insensitively and without a leading namespace separator. |
| `call_kinds` | no | Defaults to `function`. |
| `argument` | no | Optional literal-string matcher for one argument. |

Supported call kinds are:

- `function`
- `method`
- `nullsafe_method`
- `static_method`
- `dynamic`

The current PHP IR records the method name for general static calls rather than resolving the complete class hierarchy. Use appropriate confidence for static-method rules whose target name may exist on unrelated classes.

## Argument matching

An argument matcher requires an `index` between `0` and `31` and exactly one comparison:

```toml
argument = { index = 0, string_equals = "fixed-value" }
```

or:

```toml
argument = { index = 0, string_prefix = "wp_ajax_nopriv_", case_sensitive = true }
```

Only statically resolvable literal strings and literal concatenations can match. Runtime values, source snippets and secret values are never copied into rulepack findings.

## Framework activation

A framework-restricted rule remains present in the rule registry so configuration can validate its ID, but its evaluator returns no findings unless the project detector reports one of the configured frameworks.

The built-in pack currently targets:

- Laravel
- Symfony
- WordPress

Generic rules can omit `frameworks` and apply to every PHP project.

## Fingerprints and baselines

Declarative findings use the same stable fingerprint model as compiled rules: rule ID, normalized path and semantic call target. Line numbers and source values are excluded. Severity overrides therefore remain baseline-compatible.

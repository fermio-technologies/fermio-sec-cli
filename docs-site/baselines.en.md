# Baselines & CI

!!! info "What this page covers"
    Stable fingerprints, creating/using a baseline, and a minimal CI gate pattern.

## Fingerprints

Each finding has a **stable SHA-256** fingerprint. The baseline stores fingerprints only — no source, snippets or secret values.

## Create a baseline

```bash
fermio-sec scan . --write-baseline .fermio-baseline.json
```

## Use a baseline

Findings already present in the baseline are suppressed from the report and from `--fail-on` evaluation:

```bash
fermio-sec scan . \
  --baseline .fermio-baseline.json \
  --format sarif \
  --output fermio.sarif \
  --fail-on high
```

Or via config:

```toml
[scan]
baseline = ".fermio-baseline.json"
fail_on = "high"
```

Baseline schema versions are validated before use.

## Example CI job

```yaml
- name: Fermio scan
  run: |
    fermio-sec scan . \
      --baseline .fermio-baseline.json \
      --format sarif \
      --output fermio.sarif \
      --fail-on high
```

!!! tip "Update baselines deliberately"
    Regenerate a baseline only after human triage. Treat it as accepting known debt, not silencing new regressions.

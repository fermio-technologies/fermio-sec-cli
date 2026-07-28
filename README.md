# fermio-sec-cli

`fermio-sec-cli` is the local-first static analysis CLI from Fermio Technologies.

The first release targets PHP and its main ecosystems. The core architecture remains language-neutral so future frontends can be added without rewriting the analysis engine.

## Initial scope

- Generic PHP projects
- Composer project discovery
- Laravel, Symfony and WordPress detection
- PHP parsing through Tree-sitter
- Structured syntax diagnostics
- Deterministic rule execution
- Terminal, JSON and SARIF 2.1.0 reports
- Stable SHA-256 finding fingerprints
- Local fingerprint baselines
- `.gitignore` and `.fermioignore` support
- File-count and file-size scan limits
- Local-only scans by default

## Commands

```bash
cargo run -p fermio-cli -- scan .
cargo run -p fermio-cli -- scan . --format json
cargo run -p fermio-cli -- scan . --format sarif --output fermio.sarif
cargo run -p fermio-cli -- scan . --max-files 50000 --max-file-size 2097152
cargo run -p fermio-cli -- languages
cargo run -p fermio-cli -- frameworks
cargo run -p fermio-cli -- rules
```

## Baseline workflow

Create a baseline from the current findings:

```bash
cargo run -p fermio-cli -- scan . --write-baseline .fermio-baseline.json
```

Use that baseline in CI so only new findings remain in the report and affect `--fail-on`:

```bash
cargo run -p fermio-cli -- scan . \
  --baseline .fermio-baseline.json \
  --format sarif \
  --output fermio.sarif \
  --fail-on high
```

The baseline contains only stable finding fingerprints. It does not contain source code, evidence snippets or secret values. Baseline schema versions are validated before use.

Create a `.fermioignore` file in the project root to exclude generated or application-specific paths:

```gitignore
storage/**
cache/**
generated/**
```

Default scan limits are 100,000 PHP files and 2 MiB per file. Oversized files are skipped with a diagnostic; exceeding the total file-count limit stops the scan.

See [`docs/DESIGN-v0.1.md`](docs/DESIGN-v0.1.md) for the first-version design.

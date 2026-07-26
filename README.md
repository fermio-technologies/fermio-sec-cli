# fermio-sec-cli

`fermio-sec-cli` is the local-first static analysis CLI from Fermio Technologies.

The first release targets PHP and its main ecosystems. The core architecture remains language-neutral so future frontends can be added without rewriting the analysis engine.

## Initial scope

- Generic PHP projects
- Composer project discovery
- Laravel, Symfony and WordPress detection
- PHP parsing through Tree-sitter
- Deterministic rule execution
- Terminal and JSON reports
- Stable finding fingerprints
- Local-only scans by default

## Commands

```bash
cargo run -p fermio-cli -- scan .
cargo run -p fermio-cli -- scan . --format json
cargo run -p fermio-cli -- languages
cargo run -p fermio-cli -- frameworks
```

See [`docs/DESIGN-v0.1.md`](docs/DESIGN-v0.1.md) for the first-version design.

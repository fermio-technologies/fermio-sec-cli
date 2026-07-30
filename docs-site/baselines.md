# Baselines & CI

!!! info "O que esta página cobre"
    Fingerprints estáveis, criação/uso de baseline e um padrão mínimo de gate em CI.

## Fingerprints

Cada finding possui fingerprint **SHA-256 estável**. A baseline guarda apenas fingerprints — sem código-fonte, snippets ou valores secretos.

## Criar baseline

```bash
fermio-sec scan . --write-baseline .fermio-baseline.json
```

## Usar baseline

Findings já presentes na baseline são suprimidos do relatório e do cálculo de `--fail-on`:

```bash
fermio-sec scan . \
  --baseline .fermio-baseline.json \
  --format sarif \
  --output fermio.sarif \
  --fail-on high
```

Ou via config:

```toml
[scan]
baseline = ".fermio-baseline.json"
fail_on = "high"
```

Versões de schema da baseline são validadas antes do uso.

## Exemplo de job CI

```yaml
- name: Fermio scan
  run: |
    fermio-sec scan . \
      --baseline .fermio-baseline.json \
      --format sarif \
      --output fermio.sarif \
      --fail-on high
```

!!! tip "Atualizar a baseline com consciência"
    Regenere a baseline só depois de triagem humana. Tratar baseline como “aceitar dívida conhecida”, não como silenciar regressões novas.

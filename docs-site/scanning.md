# Escaneando

!!! info "O que esta página cobre"
    Como rodar `fermio-sec scan`, formatos de saída, limites de recursos, ignores e comportamento de falha por severidade.

## Comando básico

```bash
fermio-sec scan [PATH]
```

`PATH` padrão: `.` (diretório atual).

## Formatos de saída

| Valor | Uso |
|---|---|
| `terminal` (default) | relatório legível no stdout |
| `json` | relatório estruturado |
| `sarif` | SARIF 2.1.0 (Code Scanning / viewers) |

```bash
fermio-sec scan . --format json
fermio-sec scan . --format sarif --output fermio.sarif
```

`--output` grava o relatório no arquivo indicado. Sem `--output`, a saída vai para stdout.

## Limites de recursos

| Flag / config | Default | Comportamento |
|---|---|---|
| `--max-files` / `scan.max_files` | `100000` | exceder o limite **interrompe** o scan (exit `2`) |
| `--max-file-size` / `scan.max_file_size` | `2097152` (2 MiB) | arquivos maiores são **pulados** com diagnóstico `SCAN-LIMIT-001` |

```bash
fermio-sec scan . --max-files 50000 --max-file-size 1048576
```

## Vendor e ignores

Por padrão, `vendor/` não é incluído. Force com:

```bash
fermio-sec scan . --include-vendor
```

Crie `.fermioignore` na raiz do projeto (sintaxe estilo gitignore):

```gitignore
storage/**
cache/**
generated/**
```

O scanner também respeita `.gitignore`.

## Falha por severidade

```bash
fermio-sec scan . --fail-on high
```

Valores: `low`, `medium`, `high`, `critical`. O scan falha quando existe finding na severidade configurada ou acima (após baseline, se houver).

Overrides de severidade em `.fermio.toml` afetam o relatório e o limiar de falha, mas **não** alteram fingerprints nem a compatibilidade da baseline.

## Precedência CLI vs config

1. Flags explícitas da CLI
2. Valores em `.fermio.toml` (ou `--config`)
3. Defaults embutidos

`--no-config` desativa o carregamento de configuração do projeto.

## Inventário auxiliar

```bash
fermio-sec languages
fermio-sec frameworks
fermio-sec rules
```

Úteis para listar capacidades e IDs de regras registradas antes de filtrar em config.

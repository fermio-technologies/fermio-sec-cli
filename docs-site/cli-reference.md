# Referência CLI

!!! info "O que esta página cobre"
    Catálogo dos comandos e flags reais do binário `fermio-sec` (v0.1.0-rc.1).

## `fermio-sec`

```text
fermio-sec <COMMAND>
```

| Opção global | Descrição |
|---|---|
| `-h`, `--help` | ajuda |
| `-V`, `--version` | versão |

### Comandos

| Comando | Descrição |
|---|---|
| `scan` | analisa um caminho de projeto |
| `languages` | lista linguagens suportadas |
| `frameworks` | lista frameworks detectáveis / conhecidos |
| `rules` | lista regras registradas |
| `help` | ajuda de subcomando |

## `fermio-sec scan`

```text
fermio-sec scan [OPTIONS] [PATH]
```

| Flag / argumento | Tipo | Default | Descrição |
|---|---|---|---|
| `[PATH]` | path | `.` | raiz do scan |
| `--format <FORMAT>` | enum | `terminal` | `terminal` \| `json` \| `sarif` |
| `--output <OUTPUT>` | path | — | arquivo de saída do relatório |
| `--fail-on <FAIL_ON>` | enum | — | `low` \| `medium` \| `high` \| `critical` |
| `--include-vendor` | bool | `false` | inclui `vendor/` |
| `--max-files <N>` | int | config/default | limite total de arquivos PHP |
| `--max-file-size <N>` | bytes | config/default | tamanho máximo por arquivo |
| `--config <FILE>` | path | `.fermio.toml` se existir | arquivo de configuração |
| `--no-config` | bool | `false` | não carrega config do projeto |
| `--baseline <FILE>` | path | — | baseline de fingerprints |
| `--write-baseline <FILE>` | path | — | grava baseline a partir do scan atual |

### Códigos de saída (resumo)

| Código | Significado típico |
|---|---|
| `0` | sucesso (sem falha por `--fail-on`) |
| `2` | erro de configuração / limite fail-closed (ex.: `max-files`) |

## `fermio-sec languages`

Lista frontends de linguagem disponíveis (hoje: PHP).

## `fermio-sec frameworks`

Lista frameworks conhecidos para detecção/perfil.

## `fermio-sec rules`

Lista IDs de regras registradas (core + builtins + packs carregáveis no contexto da CLI).

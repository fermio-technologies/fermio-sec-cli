# Configuração

!!! info "O que esta página cobre"
    Schema versionado do `.fermio.toml`, resolução de caminhos, seleção de regras e fail-closed em erros de configuração.

## Onde a config é lida

1. Se `--config <FILE>` for passado, esse arquivo é usado.
2. Caso contrário, se existir `.fermio.toml` na raiz do scan, ele é carregado.
3. `--no-config` desativa o carregamento.

Campos desconhecidos, `schema_version` não suportado, limites inválidos, seleção conflitante de regras, rulepacks duplicados ou IDs desconhecidos **interrompem** o scan com exit code `2`.

## Exemplo

```toml
schema_version = 1

[scan]
include_vendor = false
max_files = 100000
max_file_size = 2097152
fail_on = "high"
baseline = ".fermio-baseline.json"

[rules]
# Omita `enabled` para rodar todas as regras registradas.
enabled = [
  "FERMIO-PHP-TAINT-SQL-001",
  "FERMIO-PHP-TAINT-SQL-OO-001",
  "FERMIO-WORDPRESS-AJAX-NOPRIV-001",
]
disabled = []

[rules.severity]
"FERMIO-PHP-TAINT-SQL-OO-001" = "critical"

[rulepacks]
builtins = true
paths = ["security/company-rulepack.toml"]
```

Há um ponto de partida completo em [`fermio.example.toml`](https://github.com/fermio-technologies/fermio-sec-cli/blob/main/fermio.example.toml) no repositório.

## Resolução de caminhos

Caminhos em `scan.baseline` e `rulepacks.paths` são resolvidos **relativos ao diretório do arquivo de configuração**, não ao CWD do processo.

## Seleção de regras

| Campo | Efeito |
|---|---|
| `rules.enabled` | se presente, apenas essas regras (mais as não listadas em `disabled`) |
| `rules.disabled` | remove regras da seleção |
| `rules.severity` | override de severidade por ID |

!!! warning "Conflito enabled/disabled"
    O mesmo ID em `enabled` e `disabled` é erro de configuração (fail-closed).

IDs de rulepacks externos podem ser referenciados em `enabled` / `disabled` / `severity` porque os packs são carregados **antes** da validação das regras.

## Rulepacks na config

```toml
[rulepacks]
builtins = true
paths = ["security/company-rulepack.toml"]
```

- `builtins = true` (default): inclui o rulepack de frameworks embutido.
- `builtins = false`: apenas regras core compiladas + packs locais listados.

Detalhes do schema de packs: [Rulepacks](rulepacks.md).

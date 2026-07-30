# Rulepacks

!!! info "O que esta página cobre"
    Boundary de segurança, schema TOML v1, carregamento via `.fermio.toml` e exemplos de regras declarativas.

## Boundary de segurança

Rulepacks são documentos TOML **somente dados**. Schema v1 **não** permite:

- scripts ou expressões executáveis;
- bibliotecas dinâmicas/nativas;
- regex arbitrária;
- URLs de rede ou downloads;
- transforms automáticos / autofix;
- acesso a variáveis de ambiente ou credenciais.

Limites: **1 MiB** por arquivo e **1.000** regras. Campos desconhecidos, IDs duplicados e metadados inválidos falham com exit `2`.

## Carregamento

```toml
[rulepacks]
builtins = true
paths = ["security/company-rulepack.toml"]
```

Caminhos relativos resolvem a partir do diretório do arquivo de configuração.

## Schema do documento

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

### Campos do pack

| Campo | Obrigatório | Descrição |
|---|---|---|
| `schema_version` | sim | deve ser `1` |
| `id` | sim | identificador não vazio |
| `version` | sim | versão de compatibilidade |
| `rules` | sim | 1–1000 regras |

### Campos da regra

| Campo | Obrigatório | Descrição |
|---|---|---|
| `id` | sim | começa com `FERMIO-`; maiúsculas, dígitos e hífens |
| `title` / `description` | sim | título e remediação |
| `severity` | sim | `low` \| `medium` \| `high` \| `critical` |
| `confidence` | sim | `low` \| `medium` \| `high` |
| `cwe` | não | forma `CWE-N` |
| `frameworks` | não | emite só se um dos frameworks for detectado |
| `targets` | sim | alvos de call normalizados |
| `call_kinds` | não | default `function` |
| `argument` | não | matcher literal de um argumento |

### Call kinds

`function`, `method`, `nullsafe_method`, `static_method`, `dynamic`

!!! note "static_method"
    O matcher de método estático registra o **nome do método**, sem resolução completa de classe. Por isso regras como Laravel `raw()` usam confiança média de propósito.

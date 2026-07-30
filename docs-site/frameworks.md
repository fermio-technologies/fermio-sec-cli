# Frameworks

!!! info "O que esta página cobre"
    Como o Fermio detecta Laravel, Symfony e WordPress, e quais regras de perfil entram com o rulepack embutido.

## Detecção

| Framework | Sinais típicos |
|---|---|
| **Laravel** | Composer com `laravel/framework` |
| **Symfony** | Composer com `symfony/framework-bundle` |
| **WordPress** | `wp-config.php`, `wp-includes/version.php` ou `wp-content/` |

```bash
fermio-sec frameworks
fermio-sec scan . --format json   # veja project.frameworks no relatório
```

## Rulepack embutido de frameworks

Com `rulepacks.builtins = true` (default):

| ID | Framework | Foco |
|---|---|---|
| `FERMIO-LARAVEL-DEBUG-DD-001` | Laravel | `dd()` |
| `FERMIO-LARAVEL-DB-RAW-001` | Laravel | expressões `raw()` |
| `FERMIO-SYMFONY-DEBUG-DUMP-001` | Symfony | `dump()` |
| `FERMIO-SYMFONY-PROCESS-SHELL-001` | Symfony | `Process::fromShellCommandline()` |
| `FERMIO-WORDPRESS-AJAX-NOPRIV-001` | WordPress | hooks `wp_ajax_nopriv_` |
| `FERMIO-WORDPRESS-DEBUG-LOG-001` | WordPress | `error_log()` direto |

Regras com restrição de framework permanecem registradas (válidas em config), mas **só emitem findings** quando o framework correspondente é detectado.

## Desativar builtins

```toml
[rulepacks]
builtins = false
paths = ["security/company-rulepack.toml"]
```

Isso mantém regras core compiladas (taint, etc.) e packs locais explícitos, sem o pack de frameworks embutido.

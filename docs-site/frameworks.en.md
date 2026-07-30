# Frameworks

!!! info "What this page covers"
    How Fermio detects Laravel, Symfony and WordPress, and which built-in profile rules apply.

## Detection

| Framework | Typical signals |
|---|---|
| **Laravel** | Composer package `laravel/framework` |
| **Symfony** | Composer package `symfony/framework-bundle` |
| **WordPress** | `wp-config.php`, `wp-includes/version.php` or `wp-content/` |

```bash
fermio-sec frameworks
fermio-sec scan . --format json   # see project.frameworks in the report
```

## Built-in framework rulepack

With `rulepacks.builtins = true` (default):

| ID | Framework | Focus |
|---|---|---|
| `FERMIO-LARAVEL-DEBUG-DD-001` | Laravel | `dd()` |
| `FERMIO-LARAVEL-DB-RAW-001` | Laravel | `raw()` expressions |
| `FERMIO-SYMFONY-DEBUG-DUMP-001` | Symfony | `dump()` |
| `FERMIO-SYMFONY-PROCESS-SHELL-001` | Symfony | `Process::fromShellCommandline()` |
| `FERMIO-WORDPRESS-AJAX-NOPRIV-001` | WordPress | `wp_ajax_nopriv_` hooks |
| `FERMIO-WORDPRESS-DEBUG-LOG-001` | WordPress | direct `error_log()` |

Framework-restricted rules stay registered for config validation but **only emit findings** when the matching framework is detected.

## Disable builtins

```toml
[rulepacks]
builtins = false
paths = ["security/company-rulepack.toml"]
```

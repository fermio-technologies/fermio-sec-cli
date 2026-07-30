# Taint analysis

!!! info "What this page covers"
    Source→sink analyses for command injection, SQL (procedural and OO) and reflected XSS, including sanitizers and current limits.

## Command injection — `FERMIO-PHP-TAINT-CMD-001`

Follows PHP superglobal input through indexed reads, assignments, variables and concatenation into sinks such as `system`, `exec` and `shell_exec`.

Command-domain sanitizers: `escapeshellarg()`, `escapeshellcmd()`. A value sanitized for command use **remains tainted** for SQL/HTML.

## Procedural SQL — `FERMIO-PHP-TAINT-SQL-001`

Reports when superglobal input reaches the SQL argument of procedural query APIs (`mysql_query`, `mysqli_*`, `pg_*`, `odbc_exec`, `sqlsrv_*`, etc.).

Procedural SQL sanitizers do not neutralize command/XSS. `prepare` is **not** treated as safe by name alone: tainted SQL structure passed to `pg_prepare` / `sqlsrv_prepare` is still reported.

## OO SQL (PDO / MySQLi) — `FERMIO-PHP-TAINT-SQL-OO-001`

Coverage when the frontend proves the receiver originated from `new PDO`, `new mysqli`, a direct alias, or inline creation.

Initial sinks: `PDO::query|exec|prepare`, `mysqli::query|real_query|multi_query|execute_query|prepare`.

Sanitizers: `PDO::quote`, `mysqli::real_escape_string` / `escape_string` (+ procedural SQL sanitizers).

!!! warning "Conservative receiver proof"
    Generic calls like `$service->query($sql)` are ignored. Reassignment clears the inferred type. Namespaced classes such as `App\PDO` are not native `PDO`. DI, typed properties and cross-file resolution are deferred.

## Reflected XSS — `FERMIO-PHP-TAINT-XSS-001`

Superglobal input reaching `echo` / `print` without recognized HTML encoding (`htmlspecialchars`, `htmlentities`).

Multi-expression `echo` emits at most **one** finding per statement. `print` is modeled as a sink with an independent return value.

## Same-file function summaries

Named same-file functions receive return and sink summaries to a bounded fixed point — enough for short helpers. Method bodies, closures and cross-file namespaces are not modeled yet.

SARIF includes redacted `codeFlows` (no runtime values or source snippets).

# Análise de taint

!!! info "O que esta página cobre"
    Análises source→sink de command injection, SQL (procedural e OO) e XSS refletido, incluindo sanitizers e limites atuais.

## Command injection — `FERMIO-PHP-TAINT-CMD-001`

Segue input de superglobais por leituras indexadas, assignments, variáveis e concatenação até sinks como `system`, `exec` e `shell_exec`.

Sanitizers de domínio command: `escapeshellarg()`, `escapeshellcmd()`. Valor sanitizado para command **permanece tainted** para SQL/HTML.

## SQL procedural — `FERMIO-PHP-TAINT-SQL-001`

Reporta quando input de superglobal alcança o argumento SQL de APIs procedurais (`mysql_query`, família `mysqli_*`, `pg_*`, `odbc_exec`, `sqlsrv_*`, etc.).

Sanitizers SQL procedurais não neutralizam command/XSS. `prepare` **não** é tratado como seguro só pelo nome: SQL estrutural tainted em `pg_prepare` / `sqlsrv_prepare` ainda é reportado.

## SQL OO (PDO / MySQLi) — `FERMIO-PHP-TAINT-SQL-OO-001`

Cobertura quando o frontend prova que o receiver veio de `new PDO`, `new mysqli`, alias direto ou criação inline.

Sinks iniciais: `PDO::query|exec|prepare`, `mysqli::query|real_query|multi_query|execute_query|prepare`.

Sanitizers: `PDO::quote`, `mysqli::real_escape_string` / `escape_string` (+ sanitizers procedurais SQL).

!!! warning "Prova conservadora de receiver"
    Chamadas genéricas como `$service->query($sql)` são ignoradas. Reassignment limpa o tipo. Classes namespaced tipo `App\PDO` não são a `PDO` nativa. DI, typed properties e resolução cross-file ficam para depois.

## XSS refletido — `FERMIO-PHP-TAINT-XSS-001`

Input de superglobal em `echo` / `print` sem encoding HTML reconhecido (`htmlspecialchars`, `htmlentities`).

`echo` com múltiplas expressões gera no máximo **um** finding por statement. `print` é modelado como sink com valor de retorno independente.

## Function summaries (mesmo arquivo)

Funções nomeadas no mesmo arquivo recebem summaries de retorno e de sink até um ponto fixo limitado — o suficiente para helpers curtos. Não modela ainda method bodies, closures, namespaces cross-file, etc.

SARIF inclui `codeFlows` redigidos (sem valores em runtime nem snippets de fonte).

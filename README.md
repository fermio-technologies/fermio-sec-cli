<div align="center">

# Fermio Sec CLI

### Local-first. Sem executar a aplicação.

**Análise estática para PHP — Laravel, Symfony e WordPress — com findings determinísticos, fingerprints estáveis e saída terminal / JSON / SARIF.**

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/fermio-technologies/fermio-sec-cli?include_prereleases)](https://github.com/fermio-technologies/fermio-sec-cli/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/fermio-technologies/fermio-sec-cli/ci.yml?branch=main&label=CI)](https://github.com/fermio-technologies/fermio-sec-cli/actions/workflows/ci.yml)

[![Docs PT](https://img.shields.io/badge/DOCS-PORTUGU%C3%8AS-FFCC00?style=for-the-badge&logo=readthedocs&logoColor=white)](https://fermio-technologies.github.io/fermio-sec-cli/)
[![Docs EN](https://img.shields.io/badge/DOCS-ENGLISH-2ea44f?style=for-the-badge&logo=readthedocs&logoColor=white)](https://fermio-technologies.github.io/fermio-sec-cli/en/)

> **v0.1.0-rc.1** — primeiro release candidate: scan PHP local-first, perfis Laravel/Symfony/WordPress, taint command/SQL/XSS, rulepacks declarativos, baselines e archives multiplataforma com SHA-256. Licença **AGPL-3.0-only**. Ver [CHANGELOG](CHANGELOG.md).

[**Quickstart**](#-quickstart-em-2-minutos) ·
[**O problema**](#-o-problema) ·
[**Como funciona**](#-como-funciona) ·
[**Recursos**](#-recursos) ·
[**Configuração**](#-configuração) ·
[**CI & baseline**](#-ci--baseline) ·
[**Docs**](#-documentação)

</div>

---

## ⚡ Quickstart em 2 minutos

### Opção 1 — Instalador one-line (recomendado)

```bash
# 1. Instale o binário (Linux / macOS)
curl -fsSL https://raw.githubusercontent.com/fermio-technologies/fermio-sec-cli/main/scripts/install.sh | sh

# 2. Escaneie o projeto
cd meu-projeto-php
fermio-sec scan .

# 3. Gere SARIF para o CI / Code Scanning
fermio-sec scan . --format sarif --output fermio.sarif --fail-on high
```

> **Versão específica?**
> ```bash
> curl -fsSL https://raw.githubusercontent.com/fermio-technologies/fermio-sec-cli/main/scripts/install.sh \
>   | sh -s -- --version v0.1.0-rc.1
> ```
>
> **Windows?** Baixe o `.zip` em [Releases](https://github.com/fermio-technologies/fermio-sec-cli/releases) e siga o [`INSTALL.md`](INSTALL.md).

### Opção 2 — Build a partir do código

```bash
git clone https://github.com/fermio-technologies/fermio-sec-cli.git
cd fermio-sec-cli
cargo build --locked --release -p fermio-cli
./target/release/fermio-sec scan .
```

Pronto. Você está usando Fermio.

---

## 🎯 O problema

Scanners de segurança em PHP costumam cair em um destes extremos:

| SaaS / agente remoto | Grep / regex local |
|---|---|
| Código sobe para a nuvem | Rápido, mas **muito falso positivo** |
| Setup pesado, vendor lock-in | Sem fluxo source→sink real |
| Difícil auditar o que rodou | Sem fingerprints estáveis para CI |

**Fermio preenche o gap:** análise estática **local**, com regras determinísticas, taint limitado e saída pronta para pipeline — **sem executar** PHP, Composer ou bootstrap da aplicação.

---

## 🚀 Como funciona

```
┌──────────────────────────────────────────────────────────────────────────┐
│                                                                          │
│   CÓDIGO LOCAL  →  DETECÇÃO  →  PARSE  →  REGRAS + TAINT  →  RELATÓRIO │
│   ────────────     ────────     ─────     ──────────────     ─────────   │
│   PHP / Composer   Laravel      Tree-     built-ins +        terminal    │
│   WordPress layout Symfony      sitter    rulepacks +        JSON        │
│                    WP           PHP       fingerprints       SARIF       │
│                                                                          │
│                         ↓ nunca executa a aplicação ↓                    │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

| Camada | O que faz | Resultado |
|------|-----------|-----------|
| **Detecção** | Composer + layout WordPress | perfil do projeto / frameworks |
| **Parse** | Tree-sitter PHP | IR + diagnósticos de sintaxe |
| **Regras** | core + rulepacks TOML (somente dados) | findings determinísticos |
| **Taint** | command / SQL / XSS refletido | fluxos source→sink |
| **Saída** | terminal, JSON, SARIF 2.1.0 | fingerprints SHA-256 |

> 💡 **Princípio central:** o código permanece na máquina. Rulepacks não têm scripts, rede nem plugins nativos. Baselines guardam só fingerprints — sem snippets nem segredos.

---

## ✨ Recursos

| Área | Incluso no RC |
|---|---|
| **Ecossistemas** | PHP genérico, Composer, Laravel, Symfony, WordPress |
| **Relatórios** | terminal, JSON, SARIF 2.1.0 com `codeFlows` redigidos |
| **Taint** | command injection, SQL procedural + PDO/MySQLi, XSS refletido |
| **Rulepacks** | TOML declarativo, fail-closed, limite 1 MiB / 1.000 regras |
| **CI** | `--fail-on`, baselines, `.fermioignore` + `.gitignore` |
| **Limites** | `max_files`, `max_file_size` (fail-closed / skip com diagnóstico) |
| **Targets** | Linux x86_64, Windows x86_64, macOS Intel, Apple Silicon |

Inventário rápido:

```bash
fermio-sec languages
fermio-sec frameworks
fermio-sec rules
```

Detalhes de taint, frameworks e schema de rulepacks: [documentação](https://fermio-technologies.github.io/fermio-sec-cli/).

---

## ⚙️ Configuração

O Fermio lê `.fermio.toml` na raiz do scan (ou `--config`). Flags da CLI têm precedência. Config inválida **falha fechada** (exit `2`).

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
disabled = []

[rules.severity]
"FERMIO-PHP-TAINT-SQL-OO-001" = "critical"

[rulepacks]
builtins = true
paths = ["security/company-rulepack.toml"]
```

Modelo completo: [`fermio.example.toml`](fermio.example.toml) · docs: [Configuração](https://fermio-technologies.github.io/fermio-sec-cli/configuration/).

---

## 🧪 CI & baseline

```bash
# Captura a dívida conhecida (só fingerprints)
fermio-sec scan . --write-baseline .fermio-baseline.json

# Gate: só findings novos afetam --fail-on
fermio-sec scan . \
  --baseline .fermio-baseline.json \
  --format sarif \
  --output fermio.sarif \
  --fail-on high
```

Ignore gerados:

```gitignore
# .fermioignore
storage/**
cache/**
generated/**
```

---

## 🔒 Modelo de segurança

O scanner trata fontes, configs e rulepacks como **input não confiável**. Em especial, **não**:

- executa PHP ou scripts Composer;
- carrega plugins nativos de rulepack;
- exige rede para scan local;
- grava snippets ou valores runtime em baselines.

Mais em [Modelo de segurança](https://fermio-technologies.github.io/fermio-sec-cli/security-model/) e [`SECURITY.md`](SECURITY.md).

---

## 📚 Documentação

| | |
|---|---|
| **Site** | [PT](https://fermio-technologies.github.io/fermio-sec-cli/) · [EN](https://fermio-technologies.github.io/fermio-sec-cli/en/) |
| **Instalação** | [`INSTALL.md`](INSTALL.md) |
| **Changelog** | [`CHANGELOG.md`](CHANGELOG.md) |
| **Release** | [`docs/RELEASE.md`](docs/RELEASE.md) |
| **Design / roadmap** | [`docs/DESIGN-v0.1.md`](docs/DESIGN-v0.1.md) · [`docs/ROADMAP.md`](docs/ROADMAP.md) |

---

## 📦 Licença

`fermio-sec-cli` é licenciado sob a [GNU Affero General Public License v3.0 only](LICENSE) (`AGPL-3.0-only`).

Built by [Fermio Technologies](https://github.com/fermio-technologies).

# Modelo de segurança

!!! info "O que esta página cobre"
    Trust boundary do scanner, o que a CLI nunca faz, e práticas de verificação de release.

## Trust boundary

O Fermio trata como **input não confiável**:

- repositórios escaneados;
- fontes PHP, manifests Composer, configs, ignores e rulepacks.

## A CLI não deve

- executar PHP ou scripts Composer;
- seguir symbolic links por padrão;
- carregar plugins nativos/executáveis de rulepack;
- exigir rede para um scan local;
- imprimir valores de secretos detectados em claro;
- gravar snippets de fonte ou valores runtime em baselines.

## Rulepacks

Somente dados versionados. Sem scripts, sem rede, sem libs nativas. Ver [Rulepacks](rulepacks.md).

## Releases

Archives oficiais vêm com checksums SHA-256. Verifique antes de instalar ([Começando](getting-started.md)).

## Reportar vulnerabilidades

Use o canal privado descrito em [`SECURITY.md`](https://github.com/fermio-technologies/fermio-sec-cli/blob/main/SECURITY.md). Não abra issue pública com detalhes exploráveis.

## Licença

O projeto é **AGPL-3.0-only**. Código público com copyleft Affero: modificações oferecidas em rede devem disponibilizar o código correspondente sob a mesma licença.

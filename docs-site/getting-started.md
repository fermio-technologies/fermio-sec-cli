# Começando

!!! info "O que esta página cobre"
    Pré-requisitos, instalação a partir de release ou código-fonte, verificação do binário e o primeiro `fermio-sec scan`.

## Pré-requisitos

- Sistema suportado: Linux x86_64, Windows x86_64, macOS Intel ou Apple Silicon.
- Para build a partir do código: **Rust 1.88.0** (ver `rust-toolchain.toml`).
- Um projeto PHP local para escanear (Composer opcional; WordPress também é detectado por layout).

## Instalação a partir do release

Tagged releases publicam archives para:

| Target | Arquivo típico |
|---|---|
| Linux x86_64 | `…-x86_64-unknown-linux-gnu.tar.gz` |
| Windows x86_64 | `…-x86_64-pc-windows-msvc.zip` |
| macOS Intel | `…-x86_64-apple-darwin.tar.gz` |
| macOS Apple Silicon | `…-aarch64-apple-darwin.tar.gz` |

Cada archive inclui `fermio-sec`, `README.md`, `INSTALL.md`, `CHANGELOG.md` e `LICENSE`, com um `.sha256` irmão.

### Verificar o checksum

=== "Linux"

    ```bash
    sha256sum -c fermio-sec-*.tar.gz.sha256
    ```

=== "macOS"

    ```bash
    shasum -a 256 -c fermio-sec-*.tar.gz.sha256
    ```

=== "Windows PowerShell"

    ```powershell
    $archive = Get-ChildItem fermio-sec-*.zip | Select-Object -First 1
    $expected = (Get-Content "$($archive.Name).sha256").Split(' ')[0]
    $actual = (Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected) { throw "Checksum mismatch" }
    ```

### Instalar no PATH

=== "Linux / macOS"

    ```bash
    tar -xzf fermio-sec-*.tar.gz
    sudo install -m 0755 fermio-sec-*/fermio-sec /usr/local/bin/fermio-sec
    fermio-sec --version
    ```

=== "Windows"

    ```powershell
    Expand-Archive fermio-sec-*.zip -DestinationPath .
    # Mova fermio-sec.exe para um diretório no PATH
    fermio-sec.exe --version
    ```

## Build a partir do código

```bash
git clone https://github.com/fermio-technologies/fermio-sec-cli.git
cd fermio-sec-cli
cargo build --locked --release -p fermio-cli
./target/release/fermio-sec --version
```

!!! tip "Lockfile versionado"
    O repositório inclui `Cargo.lock`. Prefira sempre `cargo … --locked` para builds reproduzíveis.

## Primeiro scan

```bash
fermio-sec scan .
fermio-sec scan . --format json
fermio-sec scan . --format sarif --output fermio.sarif --fail-on high
```

!!! warning "Sem execução de aplicação"
    O Fermio faz **apenas** análise estática. Não executa PHP, scripts Composer nem bootstrap da aplicação.

## Próximos passos

- [Escaneando](scanning.md) — formatos, limites e ignores
- [Configuração](configuration.md) — `.fermio.toml`
- [Baselines & CI](baselines.md) — fingerprints e gate de CI
- [Referência CLI](cli-reference.md) — flags completas

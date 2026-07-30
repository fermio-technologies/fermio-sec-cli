# Getting started

!!! info "What this page covers"
    Prerequisites, install from release or source, binary verification, and the first `fermio-sec scan`.

## Prerequisites

- Supported OS: Linux x86_64, Windows x86_64, macOS Intel or Apple Silicon.
- For source builds: **Rust 1.88.0** (see `rust-toolchain.toml`).
- A local PHP project to scan (Composer optional; WordPress is also detected by layout).

## Install from a release

Tagged releases publish archives for:

| Target | Typical file |
|---|---|
| Linux x86_64 | `…-x86_64-unknown-linux-gnu.tar.gz` |
| Windows x86_64 | `…-x86_64-pc-windows-msvc.zip` |
| macOS Intel | `…-x86_64-apple-darwin.tar.gz` |
| macOS Apple Silicon | `…-aarch64-apple-darwin.tar.gz` |

Each archive includes `fermio-sec`, `README.md`, `INSTALL.md`, `CHANGELOG.md` and `LICENSE`, plus a sibling `.sha256` file.

### Verify the checksum

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

### Install on PATH

=== "Linux / macOS"

    ```bash
    tar -xzf fermio-sec-*.tar.gz
    sudo install -m 0755 fermio-sec-*/fermio-sec /usr/local/bin/fermio-sec
    fermio-sec --version
    ```

=== "Windows"

    ```powershell
    Expand-Archive fermio-sec-*.zip -DestinationPath .
    # Move fermio-sec.exe into a directory on PATH
    fermio-sec.exe --version
    ```

## Build from source

```bash
git clone https://github.com/fermio-technologies/fermio-sec-cli.git
cd fermio-sec-cli
cargo build --locked --release -p fermio-cli
./target/release/fermio-sec --version
```

!!! tip "Versioned lockfile"
    The repository includes `Cargo.lock`. Prefer `cargo … --locked` for reproducible builds.

## First scan

```bash
fermio-sec scan .
fermio-sec scan . --format json
fermio-sec scan . --format sarif --output fermio.sarif --fail-on high
```

!!! warning "No application execution"
    Fermio performs **static analysis only**. It does not execute PHP, Composer scripts or application bootstrap code.

## Next steps

- [Scanning](scanning.md) — formats, limits and ignores
- [Configuration](configuration.md) — `.fermio.toml`
- [Baselines & CI](baselines.md) — fingerprints and CI gates
- [CLI reference](cli-reference.md) — full flags

# Install Fermio Sec CLI

## One-line install (Linux / macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/fermio-technologies/fermio-sec-cli/main/scripts/install.sh | sh
```

The script detects your OS/architecture, downloads the matching GitHub Release archive, verifies the SHA-256 checksum, and installs `fermio-sec` to `~/.local/bin` (adding PATH setup when needed).

Useful variants:

```bash
# Specific version
curl -fsSL https://raw.githubusercontent.com/fermio-technologies/fermio-sec-cli/main/scripts/install.sh | sh -s -- --version v0.1.0-rc.1

# Custom install directory
curl -fsSL https://raw.githubusercontent.com/fermio-technologies/fermio-sec-cli/main/scripts/install.sh | sh -s -- --bin-dir "$HOME/bin"

# Do not edit shell startup files
curl -fsSL https://raw.githubusercontent.com/fermio-technologies/fermio-sec-cli/main/scripts/install.sh | sh -s -- --no-modify-path
```

Environment alternatives: `FERMIO_VERSION`, `FERMIO_BIN_DIR`, `FERMIO_INSTALL_NO_MODIFY_PATH=1`.

Windows is not covered by the shell installer — use the `.zip` archive below.

## Supported release archives

Tagged releases publish the following targets:

- Linux x86_64: `x86_64-unknown-linux-gnu`
- Windows x86_64: `x86_64-pc-windows-msvc`
- macOS Intel: `x86_64-apple-darwin`
- macOS Apple Silicon: `aarch64-apple-darwin`

Each archive contains the `fermio-sec` executable, `README.md`, `INSTALL.md`, `CHANGELOG.md` and `LICENSE`. Every archive has a sibling `.sha256` checksum file. The dependency lockfile used for the release is also published with its checksum.

## Verify an archive

Linux:

```bash
sha256sum -c fermio-sec-*.tar.gz.sha256
```

macOS:

```bash
shasum -a 256 -c fermio-sec-*.tar.gz.sha256
```

Windows PowerShell:

```powershell
$archive = Get-ChildItem fermio-sec-*.zip | Select-Object -First 1
$expected = (Get-Content "$($archive.Name).sha256").Split(' ')[0]
$actual = (Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw "Checksum mismatch" }
```

## Install manually

Extract the archive and move the executable to a directory in your `PATH`.

Linux or macOS:

```bash
tar -xzf fermio-sec-*.tar.gz
sudo install -m 0755 fermio-sec-*/fermio-sec /usr/local/bin/fermio-sec
fermio-sec --version
```

Windows PowerShell:

```powershell
Expand-Archive fermio-sec-*.zip -DestinationPath .
# Move fermio-sec.exe to a directory included in PATH.
fermio-sec.exe --version
```

## Build from source

Rust `1.88.0` is the supported toolchain for this release candidate.

```bash
cargo build --locked --release -p fermio-cli
./target/release/fermio-sec --version
```

## First scan

```bash
fermio-sec scan .
fermio-sec scan . --format sarif --output fermio.sarif --fail-on high
```

Fermio performs static analysis only. It does not execute PHP files, Composer scripts or application bootstrap code.

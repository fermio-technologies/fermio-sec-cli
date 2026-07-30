#!/bin/sh
# Fermio Sec CLI installer
# usage: curl -fsSL https://raw.githubusercontent.com/fermio-technologies/fermio-sec-cli/main/scripts/install.sh | sh
set -eu

REPO="${FERMIO_REPO:-fermio-technologies/fermio-sec-cli}"
BIN_NAME="fermio-sec"
BIN_DIR="${FERMIO_BIN_DIR:-${HOME:-}/.local/bin}"
VERSION="${FERMIO_VERSION:-}"
MODIFY_PATH=1
API_BASE="https://api.github.com/repos/${REPO}"
DOWNLOAD_BASE="https://github.com/${REPO}/releases/download"

log() {
  printf '%s\n' "$*" >&2
}

fail() {
  log "error: $*"
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

usage() {
  cat <<'USAGE'
usage: curl -fsSL https://raw.githubusercontent.com/fermio-technologies/fermio-sec-cli/main/scripts/install.sh | sh
       curl -fsSL …/install.sh | sh -s -- [options]

Installs the fermio-sec CLI from GitHub Releases, verifies the SHA-256
checksum, and places the binary in ~/.local/bin by default.

Prerequisites:
  curl, tar, install, mktemp, uname
  sha256sum or shasum

Options:
  --version TAG        Install a specific tag (example: v0.1.0-rc.1)
  --bin-dir DIR        Install directory (default: ~/.local/bin)
  --no-modify-path     Do not update shell startup files when DIR is not on PATH
  -h, --help           Show this help

Environment:
  FERMIO_VERSION       Same as --version
  FERMIO_BIN_DIR       Same as --bin-dir
  FERMIO_REPO          GitHub owner/name (default: fermio-technologies/fermio-sec-cli)
  FERMIO_INSTALL_NO_MODIFY_PATH=1
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      shift
      VERSION="${1:-}"
      test -n "$VERSION" || fail "--version requires a value"
      ;;
    --bin-dir)
      shift
      BIN_DIR="${1:-}"
      test -n "$BIN_DIR" || fail "--bin-dir requires a value"
      ;;
    --no-modify-path)
      MODIFY_PATH=0
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
  shift
done

if [ "${FERMIO_INSTALL_NO_MODIFY_PATH:-}" = "1" ]; then
  MODIFY_PATH=0
fi

test -n "$BIN_DIR" || fail "FERMIO_BIN_DIR is empty and HOME is unavailable"

need_cmd curl
need_cmd tar
need_cmd install
need_cmd mktemp
need_cmd uname

detect_target() {
  os="$(uname -s 2>/dev/null || printf unknown)"
  arch="$(uname -m 2>/dev/null || printf unknown)"
  case "$os:$arch" in
    Linux:x86_64|Linux:amd64) printf 'x86_64-unknown-linux-gnu' ;;
    Darwin:arm64|Darwin:aarch64) printf 'aarch64-apple-darwin' ;;
    Darwin:x86_64|Darwin:amd64) printf 'x86_64-apple-darwin' ;;
    *)
      fail "unsupported platform: $os/$arch (Windows: download the .zip from GitHub Releases)"
      ;;
  esac
}

download_file() {
  url="$1"
  dest="$2"
  case "$url" in
    https://*) ;;
    *) fail "refusing non-HTTPS download URL: $url" ;;
  esac
  curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --connect-timeout 20 "$url" -o "$dest"
}

sha256_file() {
  path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{ print $1 }'
    return 0
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$path" | awk '{ print $1 }'
    return 0
  fi
  fail "sha256sum or shasum is required"
}

resolve_version() {
  if [ -n "$VERSION" ]; then
    printf '%s\n' "$VERSION"
    return 0
  fi

  # Prefer the newest published release, including pre-releases (rc.*).
  # /releases/latest ignores pre-releases.
  tag="$(
    curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --connect-timeout 20 \
      -H 'Accept: application/vnd.github+json' \
      -H 'User-Agent: fermio-sec-install' \
      "${API_BASE}/releases?per_page=20" |
      awk '
        BEGIN { found = 0 }
        /"tag_name"[[:space:]]*:/ {
          line = $0
          sub(/^.*"tag_name"[[:space:]]*:[[:space:]]*"/, "", line)
          sub(/".*$/, "", line)
          if (line != "" && found == 0) {
            print line
            found = 1
            exit
          }
        }
      '
  )"
  test -n "$tag" || fail "could not resolve the latest GitHub release for ${REPO}"
  printf '%s\n' "$tag"
}

path_contains_dir() {
  needle="${1%/}"
  old_ifs="$IFS"
  IFS=:
  for entry in ${PATH:-}; do
    if [ "${entry%/}" = "$needle" ]; then
      IFS="$old_ifs"
      return 0
    fi
  done
  IFS="$old_ifs"
  return 1
}

shell_double_quote_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/`/\\`/g; s/\$/\\$/g'
}

path_setup_profile() {
  shell_name="$1"
  test -n "${HOME:-}" || return 1
  case "$shell_name" in
    zsh) printf '%s/.zshrc\n' "${ZDOTDIR:-$HOME}" ;;
    bash)
      if [ -f "$HOME/.bashrc" ]; then
        printf '%s/.bashrc\n' "$HOME"
      elif [ -f "$HOME/.bash_profile" ]; then
        printf '%s/.bash_profile\n' "$HOME"
      else
        printf '%s/.profile\n' "$HOME"
      fi
      ;;
    fish) printf '%s/.config/fish/config.fish\n' "$HOME" ;;
    *) printf '%s/.profile\n' "$HOME" ;;
  esac
}

path_setup_snippet() {
  shell_name="$1"
  dir_escaped="$(shell_double_quote_escape "$2")"
  case "$shell_name" in
    fish)
      cat <<EOF

# fermio-sec installer PATH setup
if not contains -- "$dir_escaped" \$PATH
    set -gx PATH "$dir_escaped" \$PATH
end
EOF
      ;;
    *)
      cat <<EOF

# fermio-sec installer PATH setup
case ":\${PATH}:" in
  *":$dir_escaped:"*) ;;
  *) export PATH="$dir_escaped:\${PATH}" ;;
esac
EOF
      ;;
  esac
}

print_current_path_command() {
  shell_name="$1"
  dir_escaped="$(shell_double_quote_escape "$2")"
  case "$shell_name" in
    fish) printf '  set -gx PATH "%s" $PATH\n' "$dir_escaped" >&2 ;;
    *) printf '  export PATH="%s:${PATH}"\n' "$dir_escaped" >&2 ;;
  esac
}

configure_path_if_needed() {
  dir="${BIN_DIR%/}"
  if path_contains_dir "$dir"; then
    return 0
  fi

  shell_name="${SHELL:-}"
  shell_name="${shell_name##*/}"
  [ -n "$shell_name" ] || shell_name="sh"

  if [ "$MODIFY_PATH" != "1" ]; then
    log ""
    log "$dir is not on PATH; shell startup file update skipped."
    log "For this shell session, run:"
    print_current_path_command "$shell_name" "$dir"
    return 0
  fi

  if [ -n "${GITHUB_PATH:-}" ]; then
    printf '%s\n' "$dir" >>"$GITHUB_PATH"
    log ""
    log "Added $dir to GITHUB_PATH for later GitHub Actions steps."
    return 0
  fi

  if [ "${CI:-}" = "1" ] || [ "${CI:-}" = "true" ]; then
    log ""
    log "$dir is not on PATH; CI detected, not editing shell startup files."
    log "For this shell session, run:"
    print_current_path_command "$shell_name" "$dir"
    return 0
  fi

  if ! profile="$(path_setup_profile "$shell_name")"; then
    log ""
    log "$dir is not on PATH; HOME is unavailable."
    log "For this shell session, run:"
    print_current_path_command "$shell_name" "$dir"
    return 0
  fi

  if ! grep -F "fermio-sec installer PATH setup" "$profile" >/dev/null 2>&1; then
    profile_dir="$(dirname "$profile")"
    mkdir -p "$profile_dir"
    path_setup_snippet "$shell_name" "$dir" >>"$profile"
    log ""
    log "Added fermio-sec PATH setup to $profile."
  fi

  log "$dir is not on the current PATH; restart your shell or run:"
  print_current_path_command "$shell_name" "$dir"
}

tmp_dir=
cleanup() {
  if [ -n "${tmp_dir:-}" ] && [ -d "$tmp_dir" ]; then
    rm -rf "$tmp_dir"
  fi
}
trap cleanup EXIT INT HUP TERM

target="$(detect_target)"
version="$(resolve_version)"
case "$version" in
  v*) ;;
  *) version="v${version}" ;;
esac

archive_name="${BIN_NAME}-${version}-${target}.tar.gz"
checksum_name="${archive_name}.sha256"
archive_url="${DOWNLOAD_BASE}/${version}/${archive_name}"
checksum_url="${DOWNLOAD_BASE}/${version}/${checksum_name}"

log "Installing ${BIN_NAME} ${version} for ${target}"
log "  archive: ${archive_url}"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/fermio-install.XXXXXX")"
archive_path="${tmp_dir}/${archive_name}"
checksum_path="${tmp_dir}/${checksum_name}"
extract_dir="${tmp_dir}/extract"

download_file "$archive_url" "$archive_path"
download_file "$checksum_url" "$checksum_path"

expected="$(awk '{ print $1; exit }' "$checksum_path")"
test -n "$expected" || fail "checksum file is empty: ${checksum_name}"
actual="$(sha256_file "$archive_path")"
if [ "$expected" != "$actual" ]; then
  fail "SHA-256 mismatch for ${archive_name} (expected ${expected}, got ${actual})"
fi
log "Checksum OK (${actual})"

mkdir -p "$extract_dir"
tar -xzf "$archive_path" -C "$extract_dir"

binary_path="$(find "$extract_dir" -type f -name "$BIN_NAME" | head -n 1)"
test -n "$binary_path" || fail "archive did not contain ${BIN_NAME}"

mkdir -p "$BIN_DIR"
install -m 0755 "$binary_path" "${BIN_DIR}/${BIN_NAME}"

configure_path_if_needed

log ""
log "Installed ${BIN_DIR}/${BIN_NAME}"
if command -v "$BIN_NAME" >/dev/null 2>&1 || [ -x "${BIN_DIR}/${BIN_NAME}" ]; then
  "${BIN_DIR}/${BIN_NAME}" --version >&2 || true
fi
log "Try: fermio-sec scan ."

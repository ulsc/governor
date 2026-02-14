#!/bin/sh
# Governor install script
# Usage: curl -fsSL https://governor.sh/install.sh | bash
#        INSTALL_DIR=/opt/bin curl -fsSL ... | sh
set -eu

REPO="ulsc/governor"
BINARY_NAME="governor"

# --- helpers ----------------------------------------------------------------

log()  { printf '%s\n' "$@"; }
info() { printf '\033[1;34m==>\033[0m %s\n' "$@"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$@" >&2; }
fail() { printf '\033[1;31merror:\033[0m %s\n' "$@" >&2; exit 1; }

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    fail "required command not found: $1"
  fi
}

# --- detect platform --------------------------------------------------------

detect_os() {
  case "$(uname -s)" in
    Linux*)           echo "linux" ;;
    Darwin*)          echo "darwin" ;;
    MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
    *)                fail "unsupported OS: $(uname -s)" ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)    echo "amd64" ;;
    aarch64|arm64)   echo "arm64" ;;
    *)               fail "unsupported architecture: $(uname -m)" ;;
  esac
}

# --- checksum verification -------------------------------------------------

verify_checksum() {
  archive_file="$1"
  checksums_file="$2"

  if command -v sha256sum >/dev/null 2>&1; then
    expected="$(grep "$(basename "$archive_file")" "$checksums_file" | awk '{print $1}')"
    actual="$(sha256sum "$archive_file" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    expected="$(grep "$(basename "$archive_file")" "$checksums_file" | awk '{print $1}')"
    actual="$(shasum -a 256 "$archive_file" | awk '{print $1}')"
  else
    warn "neither sha256sum nor shasum found — skipping checksum verification"
    return 0
  fi

  if [ -z "$expected" ]; then
    fail "could not find checksum for $(basename "$archive_file") in checksums file"
  fi

  if [ "$expected" != "$actual" ]; then
    fail "checksum mismatch for $(basename "$archive_file")\n  expected: $expected\n  actual:   $actual"
  fi

  info "checksum verified"
}

# --- resolve install directory ----------------------------------------------

resolve_install_dir() {
  if [ -n "${INSTALL_DIR:-}" ]; then
    echo "$INSTALL_DIR"
    return
  fi
  if [ -w /usr/local/bin ]; then
    echo "/usr/local/bin"
    return
  fi
  echo "${HOME}/.local/bin"
}

# --- main -------------------------------------------------------------------

main() {
  need_cmd curl
  need_cmd tar

  OS="$(detect_os)"
  ARCH="$(detect_arch)"

  # Windows arm64 not supported
  if [ "$OS" = "windows" ] && [ "$ARCH" = "arm64" ]; then
    fail "windows/arm64 is not supported — use windows/amd64 (x86_64)"
  fi

  # linux arm64 + darwin amd64/arm64 + linux amd64 + windows amd64
  info "detected platform: ${OS}/${ARCH}"

  # Fetch latest release tag
  info "fetching latest release..."
  RELEASE_URL="https://api.github.com/repos/${REPO}/releases/latest"
  RELEASE_JSON="$(curl -fsSL "$RELEASE_URL")" || fail "could not fetch latest release from GitHub"
  TAG="$(printf '%s' "$RELEASE_JSON" | grep '"tag_name"' | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')"

  if [ -z "$TAG" ]; then
    fail "could not determine latest release tag"
  fi

  info "latest release: ${TAG}"

  # Determine archive name and extension
  if [ "$OS" = "windows" ]; then
    ARCHIVE_EXT="zip"
    BINARY_EXT=".exe"
  else
    ARCHIVE_EXT="tar.gz"
    BINARY_EXT=""
  fi

  ARCHIVE_NAME="${BINARY_NAME}_${TAG}_${OS}_${ARCH}.${ARCHIVE_EXT}"
  CHECKSUMS_NAME="checksums_${TAG}.txt"

  DOWNLOAD_BASE="https://github.com/${REPO}/releases/download/${TAG}"
  ARCHIVE_URL="${DOWNLOAD_BASE}/${ARCHIVE_NAME}"
  CHECKSUMS_URL="${DOWNLOAD_BASE}/${CHECKSUMS_NAME}"

  # Create temp directory with cleanup trap
  TMPDIR_INSTALL="$(mktemp -d)"
  trap 'rm -rf "$TMPDIR_INSTALL"' EXIT

  # Download archive and checksums
  info "downloading ${ARCHIVE_NAME}..."
  curl -fsSL -o "${TMPDIR_INSTALL}/${ARCHIVE_NAME}" "$ARCHIVE_URL" \
    || fail "failed to download ${ARCHIVE_URL}"

  info "downloading checksums..."
  curl -fsSL -o "${TMPDIR_INSTALL}/${CHECKSUMS_NAME}" "$CHECKSUMS_URL" \
    || fail "failed to download ${CHECKSUMS_URL}"

  # Verify checksum
  verify_checksum "${TMPDIR_INSTALL}/${ARCHIVE_NAME}" "${TMPDIR_INSTALL}/${CHECKSUMS_NAME}"

  # Extract binary
  info "extracting ${BINARY_NAME}..."
  if [ "$ARCHIVE_EXT" = "zip" ]; then
    need_cmd unzip
    unzip -qo "${TMPDIR_INSTALL}/${ARCHIVE_NAME}" -d "${TMPDIR_INSTALL}"
  else
    tar -xzf "${TMPDIR_INSTALL}/${ARCHIVE_NAME}" -C "${TMPDIR_INSTALL}"
  fi

  # Install binary
  DEST_DIR="$(resolve_install_dir)"
  mkdir -p "$DEST_DIR"

  DEST_PATH="${DEST_DIR}/${BINARY_NAME}${BINARY_EXT}"
  cp "${TMPDIR_INSTALL}/${BINARY_NAME}${BINARY_EXT}" "$DEST_PATH"
  chmod +x "$DEST_PATH"

  info "installed ${BINARY_NAME} ${TAG} to ${DEST_PATH}"

  # Warn if not in PATH
  case ":${PATH}:" in
    *":${DEST_DIR}:"*) ;;
    *)
      warn "${DEST_DIR} is not in your PATH"
      log ""
      log "  Add it to your shell profile:"
      log "    export PATH=\"${DEST_DIR}:\$PATH\""
      log ""
      ;;
  esac

  info "done! Run 'governor version' to verify."
}

main "$@"

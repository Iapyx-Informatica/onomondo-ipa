#!/usr/bin/env bash
# Regenerate src/ipa/libasn/*.{c,h} from asn1/*.asn using asn1c.
#
# Two modes:
#   1. If asn1c is installed locally, use it directly.
#   2. Otherwise, fall back to running the project Dockerfile's asn1c in an
#      ephemeral container.  Requires a running Docker daemon.
#
# Run from anywhere; the script cds to the repo root first.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REPO_ROOT}"

run_regen() {
  cd "${REPO_ROOT}/asn1"
  ./regenerate_libasn.sh
}

if command -v asn1c >/dev/null 2>&1 && command -v patch >/dev/null 2>&1; then
  echo "[regen] using local asn1c: $(command -v asn1c)"
  run_regen
  exit 0
fi

if command -v docker >/dev/null 2>&1; then
  # Check the daemon is actually up.
  if docker info >/dev/null 2>&1; then
    echo "[regen] no local asn1c; running in ephemeral Ubuntu container via Docker"
    # MSYS/Git-Bash on Windows auto-converts the first /path argument in docker
    # flags, which breaks -v /host:/src and -w /src.  MSYS_NO_PATHCONV=1 disables
    # that for this one command.  Harmless on Linux/macOS shells.
    MSYS_NO_PATHCONV=1 docker run --rm \
      -v "${REPO_ROOT}:/src" \
      -w /src \
      ubuntu:24.04 \
      bash -c "apt-get update -qq \
        && apt-get install -y -qq --no-install-recommends asn1c patch >/dev/null \
        && cd /src/asn1 \
        && ./regenerate_libasn.sh"
    exit 0
  fi
  echo "[regen] Docker is installed but the daemon is not running."
  echo "[regen] Start Docker Desktop (or 'systemctl start docker') and retry."
  exit 2
fi

echo "[regen] need either 'asn1c' in PATH or a running Docker daemon." >&2
echo "[regen] on Debian/Ubuntu:  sudo apt-get install asn1c patch" >&2
exit 1

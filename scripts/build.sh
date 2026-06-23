#!/usr/bin/env bash
# End-to-end build: regenerate libasn (if needed) and compile the project.
#
# Modes:
#   ./scripts/build.sh              # local build (needs asn1c + cmake + libcurl + libpcsclite)
#   ./scripts/build.sh --docker     # containerised build (needs only Docker)
#
# The --docker mode wraps the project Dockerfile so everything happens inside
# a reproducible Ubuntu 24.04 toolchain.  Use it on Windows/macOS hosts.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

if [[ "${1-}" == "--docker" ]]; then
  echo "[build] containerised build (Ubuntu 24.04 + asn1c + cmake)"
  docker build -t onomondo-ipa:v1.2 .
  echo "[build] image built.  Extract artifacts with:"
  echo "  docker run --rm -v \"\$(pwd):/host\" onomondo-ipa:v1.2 \\"
  echo "    cp -r /src/build /host/build-docker"
  exit 0
fi

# Local build path.
"${SCRIPT_DIR}/regen.sh"

cmake -S "${REPO_ROOT}" -B "${REPO_ROOT}/build" \
  -DENABLE_SANITIZE=ON -DSHOW_ASN_OUTPUT=ON
cmake --build "${REPO_ROOT}/build" --parallel

echo
echo "[build] success: ${REPO_ROOT}/build/src/ipa/ipa"

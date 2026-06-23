#!/usr/bin/env bash
# Regression-test the build against both asn1c versions.  The two generate
# subtly different C output (OBJECT_IDENTIFIER_get_arcs signature, TYPE
# descriptor op-sub-struct, C++-keyword escaping, etc.), and it's easy to
# break one while fixing the other.  This script regenerates libasn with
# each asn1c in turn, builds the project, and runs ctest.  Exits non-zero
# if either fails.
#
# Prerequisites:
#   - Docker daemon running
#   - scripts/Dockerfile.asn1c built once:
#       docker build -t asn1c-master -f scripts/Dockerfile.asn1c scripts/
#
# Usage:
#   ./scripts/test-both-asn1c.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

# Ensure the asn1c-master image exists locally (build it once if not).
if ! docker image inspect asn1c-master >/dev/null 2>&1; then
  echo "[test-both] building asn1c-master image (one-time, ~1 min)"
  MSYS_NO_PATHCONV=1 docker build -t asn1c-master -f scripts/Dockerfile.asn1c scripts/
fi

run_one() {
  local label="$1"
  local image="$2"
  local regen_cmd="$3"
  echo
  echo "=============================================================="
  echo "  asn1c version: ${label}"
  echo "=============================================================="
  rm -rf "${REPO_ROOT}/build"
  MSYS_NO_PATHCONV=1 docker run --rm \
    -v "${REPO_ROOT}:/src" -w /src "${image}" \
    bash -c "export DEBIAN_FRONTEND=noninteractive; \
             apt-get update -qq >/dev/null 2>&1 && \
             apt-get install -y -qq --no-install-recommends \
               asn1c patch build-essential cmake \
               libcurl4-gnutls-dev libpcsclite-dev >/dev/null 2>&1 || true; \
             ${regen_cmd} && \
             cmake -S /src -B /src/build -DSHOW_ASN_OUTPUT=ON 2>&1 | grep -E 'detected' || true; \
             cmake --build /src/build 2>&1 | grep -E 'error:|FAILED|Built target' | head -20 && \
             cd /src/build && ctest --output-on-failure 2>&1 | tail -5"
}

# Pass 1: distro-packaged asn1c 0.9.28 (the version most users will have).
run_one "0.9.28 (distro/ubuntu:20.04)" "ubuntu:20.04" \
  "cd /src/asn1 && ./regenerate_libasn.sh >/dev/null 2>&1"

# Pass 2: asn1c master (what Fabio builds locally, also closer to upstream
# onomondo-ipa's original generated output).
run_one "master (built from source)" "asn1c-master" \
  "cd /src/asn1 && ./regenerate_libasn.sh >/dev/null 2>&1"

echo
echo "=============================================================="
echo "  BOTH asn1c versions built cleanly."
echo "=============================================================="

# Reproducible build for onomondo-ipa (SGP.32 v1.2 migration).
#
# Usage:
#   docker build -t onomondo-ipa .
#   docker run --rm -v "$(pwd):/host" onomondo-ipa cp -r /src/build /host/
#
# Or via the helper scripts:
#   ./scripts/regen.sh    # regenerate libasn/ from .asn sources (needs asn1c)
#   ./scripts/build.sh    # regen + cmake build
#
# Pinning to 24.04 guarantees a stable asn1c version across machines.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      asn1c \
      build-essential \
      cmake \
      libcurl4-gnutls-dev \
      libpcsclite-dev \
      libjansson-dev \
      patch \
      pkg-config \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . /src

# Regenerate libasn from the SGP.32 v1.2 .asn schema, then build.
# If you want to rebuild without regenerating, comment the first line.
RUN bash /src/scripts/regen.sh
RUN cmake -S /src -B /src/build -DENABLE_SANITIZE=ON -DSHOW_ASN_OUTPUT=ON \
 && cmake --build /src/build --parallel

# Default command: run the sample IPAd binary (override as needed).
CMD ["/src/build/src/ipa/ipa", "-h"]

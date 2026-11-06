# readsbee: drop-in for the ultrafeeder `globe` service on whereplane.xyz.
# Stock ultrafeeder (tar1090, graphs1090, mlathub, s6, every ULTRAFEEDER_/READSB_ env var)
# with readsb replaced by readsbee, built WITH_UUIDS like whereplane-xyz's old Dockerfile.
# Bases are pinned by digest; bump both together.

# docker-baseimage:mlatclient, 2026-11-05
ARG BUILD_BASE=ghcr.io/sdr-enthusiasts/docker-baseimage@sha256:eee691a5f6474450221b7fab60f6fab2a13a2960306ffd8bf628072be3ac60af
# docker-adsb-ultrafeeder:latest as run by whereplane's globe on 2026-11-05 (built 2026-03-16)
ARG RUN_BASE=ghcr.io/sdr-enthusiasts/docker-adsb-ultrafeeder@sha256:6dd174405cd1860608d9baa1e93c43f91c6c31c6a346a9c5a3349e870631ac92

FROM ${BUILD_BASE} AS build
SHELL ["/bin/bash", "-x", "-o", "pipefail", "-c"]
COPY . /src/readsbee
RUN cd /src/readsbee && \
    make clean && \
    make RTLSDR=yes WITH_UUIDS=yes AIRCRAFT_HASH_BITS=14 DISABLE_RTLSDR_ZEROCOPY_WORKAROUND=yes -j"$(nproc)" && \
    make beetest WITH_UUIDS=yes && \
    cp readsb /usr/local/bin/readsb && \
    /usr/local/bin/readsb --version

FROM ${RUN_BASE}
ARG VERSION=dev
LABEL org.opencontainers.image.source="https://github.com/PantsForBirds/readsbee" \
      org.opencontainers.image.description="ultrafeeder with readsbee (readsb fork, ADSBee-only ingest filter)" \
      org.opencontainers.image.licenses="GPL-3.0-or-later" \
      org.opencontainers.image.version="${VERSION}"
COPY --from=build /usr/local/bin/readsb /usr/local/bin/readsb
RUN /usr/local/bin/readsb --version && /usr/local/bin/readsb --help | grep -q net-require-adsbee-uuid

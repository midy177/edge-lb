FROM debian:bookworm-slim

ARG TARGETARCH

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        iproute2 \
        nftables \
        procps \
        tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY dist/docker/${TARGETARCH}/edge-lb /usr/local/bin/edge-lb
COPY deploy/config.gateway.example.toml /usr/share/edge-lb/config.gateway.example.toml
COPY deploy/config.backend.example.toml /usr/share/edge-lb/config.backend.example.toml

ENTRYPOINT ["/usr/local/bin/edge-lb"]
CMD ["--help"]

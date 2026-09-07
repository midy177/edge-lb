FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        iproute2 \
        nftables \
        procps \
        tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY edge-lb /usr/local/bin/edge-lb
COPY config.gateway.example.toml /usr/share/edge-lb/config.gateway.example.toml
COPY config.backend.example.toml /usr/share/edge-lb/config.backend.example.toml

ENTRYPOINT ["/usr/local/bin/edge-lb"]
CMD ["--help"]

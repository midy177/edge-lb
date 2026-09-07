FROM rust:1-slim-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends protobuf-compiler ca-certificates iproute2 \
    && rm -rf /var/lib/apt/lists/*

FROM debian:bookworm-slim

ARG TARGETARCH

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY dist/docker/backend-server-${TARGETARCH} /usr/local/bin/backend-server
RUN chmod +x /usr/local/bin/backend-server

EXPOSE 8080/tcp
EXPOSE 8080/udp

ENTRYPOINT ["backend-server"]
CMD ["-serve"]

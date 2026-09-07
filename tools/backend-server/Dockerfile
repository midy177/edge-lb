FROM alpine:3.22

ARG TARGETARCH

RUN apk add --no-cache ca-certificates

COPY dist/docker/backend-server-${TARGETARCH} /usr/local/bin/backend-server
RUN chmod +x /usr/local/bin/backend-server

EXPOSE 8080/tcp
EXPOSE 8080/udp

ENTRYPOINT ["backend-server"]
CMD ["-serve"]

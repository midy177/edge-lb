# backend-server utility tasks.

REPO_ROOT := $(abspath ../..)
PACKAGE   := backend-server
VERSION   := $(shell awk -F '"' '/^version[[:space:]]*=/ { print $$2; exit }' Cargo.toml)

CARGO      ?= cargo
CARGO_ZIG  ?= cargo zigbuild
INSTALL    ?= install
DOCKER     ?= docker

LISTEN     ?= 0.0.0.0:8080
PREFIX     ?= /usr/local
IMAGE_NAME ?= backend-server
IMAGE_TAG  ?= v$(VERSION)
IMAGE_REF  ?= $(IMAGE_NAME):$(IMAGE_TAG)
PLATFORM   ?= linux/amd64
IMAGE_OUTPUT ?= --push

DIST_DIR       := dist
DOCKER_DIST    := $(DIST_DIR)/docker
AMD64_TARGET   := x86_64-unknown-linux-gnu
ARM64_TARGET   := aarch64-unknown-linux-gnu
AMD64_BIN      := $(REPO_ROOT)/target/$(AMD64_TARGET)/release/$(PACKAGE)
ARM64_BIN      := $(REPO_ROOT)/target/$(ARM64_TARGET)/release/$(PACKAGE)

.PHONY: help fmt check test build release release-amd64 release-arm64 docker-stage docker-image run install clean

help:
	@echo "make fmt           - cargo fmt for backend-server"
	@echo "make check         - cargo check for backend-server"
	@echo "make test          - cargo test for backend-server"
	@echo "make build         - debug build"
	@echo "make release       - Linux amd64/arm64 release builds via cargo-zigbuild"
	@echo "make release-amd64 - Linux amd64 release build via cargo-zigbuild"
	@echo "make release-arm64 - Linux arm64 release build via cargo-zigbuild"
	@echo "make docker-stage  - copy release binaries to dist/docker for Dockerfile"
	@echo "make docker-image  - build $(IMAGE_REF) for $(PLATFORM) with $(IMAGE_OUTPUT)"
	@echo "make run           - run service on $(LISTEN)"
	@echo "make install       - install release binary to $(PREFIX)/bin"
	@echo "make clean         - remove local dist/"

fmt:
	$(CARGO) fmt --manifest-path $(REPO_ROOT)/Cargo.toml --package $(PACKAGE)

check:
	$(CARGO) check --manifest-path $(REPO_ROOT)/Cargo.toml -p $(PACKAGE)

test:
	$(CARGO) test --manifest-path $(REPO_ROOT)/Cargo.toml -p $(PACKAGE)

build:
	$(CARGO) build --manifest-path $(REPO_ROOT)/Cargo.toml -p $(PACKAGE)

release: release-amd64 release-arm64

release-amd64:
	$(CARGO_ZIG) --manifest-path $(REPO_ROOT)/Cargo.toml --release -p $(PACKAGE) --target $(AMD64_TARGET)

release-arm64:
	$(CARGO_ZIG) --manifest-path $(REPO_ROOT)/Cargo.toml --release -p $(PACKAGE) --target $(ARM64_TARGET)

docker-stage: release
	mkdir -p $(DOCKER_DIST)
	cp $(AMD64_BIN) $(DOCKER_DIST)/backend-server-amd64
	cp $(ARM64_BIN) $(DOCKER_DIST)/backend-server-arm64
	chmod 0755 $(DOCKER_DIST)/backend-server-amd64 $(DOCKER_DIST)/backend-server-arm64

docker-image: docker-stage
	$(DOCKER) buildx build --platform $(PLATFORM) $(IMAGE_OUTPUT) -t $(IMAGE_REF) .

run:
	$(CARGO) run --manifest-path $(REPO_ROOT)/Cargo.toml -p $(PACKAGE) -- -serve -listen $(LISTEN)

install: release-amd64
	$(INSTALL) -m 0755 $(AMD64_BIN) $(PREFIX)/bin/$(PACKAGE)

clean:
	rm -rf $(DIST_DIR)

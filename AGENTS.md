# Repository Guidelines

## Project Structure & Module Organization

This repository implements `edge-lb`, the native DNAT/SNAT load balancer for the verified VXLAN return-path scheme (see `docs/architecture.md` and `docs/vxlan-dscp-verified.md`). The Rust workspace at the root has three crates: `edge-lb/` (user-space CLI/daemon/HTTP API), `edge-lb-common/` (shared types), `edge-lb-ebpf/` (Rust/Aya eBPF datapath programs). `ui/` holds the Vue 3 + TypeScript + Vite (rolldown) + shadcn-vue style management panel, built with bun and embedded into the binary at compile time. `deploy/` has systemd units, package templates, compose examples, and installation helpers. `tools/` contains validation utilities such as `ha-bench` and `backend-server`.

## Build, Test, and Development Commands

- `make check`: cargo check via a Linux container (aya needs Linux libc).
- `make clippy` / `make test`: lint and tests (`test` needs `--privileged` for map creation).
- `make ebpf`: build the DSCP marker object; requires `nightly-2025-12-01` (LLVM 21 must match bpf-linker) and `cargo install bpf-linker --locked`.
- `make release`: x86_64 Linux release build via an amd64 container.
- `make ui`: bun install + vite (rolldown) build into `ui/dist`.
- `make fmt`: `cargo fmt --all`.
- `make deb`: build role-specific gateway/backend Debian packages.
- `make container-image-push`: build and push the multi-platform GHCR image.

## Coding Style & Naming Conventions

Use standard Rust 2024 formatting and keep crate names in kebab case. Rust modules, functions, and variables use `snake_case`; types use `PascalCase`. Keep eBPF code compact and kernel-friendly; prefer explicit fixed-width integer types. Shell scripts should use clear variable names for interface, port, and IP settings.

## Frontend UI Constraints

Use shadcn-vue components for interactive form controls in `ui/`. Do not hand-style native selects, checkboxes, dialogs, or similar controls when a shadcn-vue/Reka UI primitive is available. For dropdowns, use the shared shadcn-vue Select wrapper under `ui/src/components/ui/select/` so trigger, content, item, focus, disabled, and popover states stay consistent across pages.

## Native Datapath Constraints

Keep management models centered on listener configurations and target groups. Do not reintroduce external load balancer provider models, standalone backend-target APIs, or external container dependencies. Gateway datapath changes should reconcile the native eBPF maps and VXLAN return path directly from the SQLite-backed configuration model.

## Testing Guidelines

Use `cargo fmt --all --check`, `make check`, and `make test` as baseline validation. For network behavior changes, include the exact route, nftables, curl, nc, or `ha-bench` commands used to verify the topology.

## Commit & Pull Request Guidelines

No local Git history is available, so no repository-specific commit pattern can be inferred. Use short imperative subjects, for example `Fix target group reconcile`, and keep related topology, config, and documentation updates together. Pull requests should describe the tested environment, changed IP/ASN assumptions, commands run, and observed packet or BGP evidence.

## Security & Configuration Tips

Do not commit real credentials, private keys, or cloud-specific secrets. Keep example IPs, ASNs, and hostnames clearly marked, and update both compose files and BGP configs together when changing topology.

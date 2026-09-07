# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with
code in this repository.

## What This Is

edge-lb is a layer-4 load-balancing agent for cloud VPCs. It provides a native
default-mode DNAT/SNAT datapath, preserves the real client IP seen by backend
services, and returns backend replies through a VXLAN tunnel so the gateway can
perform reverse NAT back to the client.

One binary runs in two roles:

- `gateway`: owns listener configuration, target groups, the management API/UI,
  native eBPF datapath maps, DSCP marking, VXLAN hub, HA state, VIP takeover,
  BFD, and flow-state synchronization.
- `backend`: subscribes to gateway xDS, registers node identity, configures the
  VXLAN return device, nftables return marking, and policy routing.

See `docs/architecture.md` for the authoritative architecture.

## Build, Test, Lint

The dev host may be macOS, but Aya/Linux networking code is checked in a Linux
container:

- `make check`: cargo check for the workspace, excluding the eBPF crate.
- `make clippy`: clippy with warnings denied.
- `make test`: `cargo test -p edge-lb` in a privileged Linux container.
- `make fmt`: `cargo fmt --all`.
- `make ebpf`: build the eBPF object.
- `make release`: build release binaries with embedded UI and eBPF objects.
- `make ui`: install UI dependencies with bun and build `ui/dist`.
- `make deb`: build role-specific Debian packages.
- `make container-image`: build the local container image.

## Architecture

### Data Plane

```text
client -> gateway public IP/VIP:port
  -> native ingress eBPF listener match
  -> default DNAT to a selected target-group backend
  -> backend service sees the real client IP
  -> backend return marking and policy route
  -> VXLAN return path
  -> gateway native reverse NAT
  -> client
```

Only connections marked by edge-lb are returned through the tunnel. Direct
traffic to backend public or private addresses is left alone.

### Module Boundaries

- `config/`: bootstrap TOML model, defaults, validation, normalization, and
  user-facing rendering.
- `storage/`: SQLite-backed persistent configuration and transactional writes.
- `runtime/`: runtime state, discovery, HA, logging, shutdown, and HA write
  forwarding.
- `control/`: xDS-like gRPC plane and active backend registry.
- `api/`: HTTP API, auth, routing, handlers, and embedded UI serving.
- `provider/native/`: listener/target-group model, probes, native store, flow
  synchronization, and HA helpers.
- `linux/`: netlink, nftables, route, sysctl, ARP, TC, and eBPF datapath
  integration.
- `role/`: gateway/backend orchestration.
- `tools/`: validation tools such as `backend-server` and `ha-bench`.

### Source Of Truth

- Listener configurations and target groups are the management model.
- Target groups own backend targets and health probes.
- Listener configurations bind protocols, public ports, target groups, and
  target ports.
- The gateway expands runtime datapath entries from those models.
- Gateway and backend online inventory is derived from active xDS sessions, not
  from a persisted node cache.
- HA business writes are MASTER-authoritative. BACKUP writes are forwarded to
  MASTER and then replicated back.

## Cross-Cutting Constraints

- Do not reintroduce external load balancer providers, standalone
  backend-target APIs, or container-runtime dependencies.
- UI interactive controls must use the shadcn-vue/Reka UI primitives under
  `ui/src/components/ui/`.
- Rust crates use edition 2024, kebab-case crate names, and standard formatting.
- Docs in `docs/` are mostly Chinese; keep additions consistent with each file.

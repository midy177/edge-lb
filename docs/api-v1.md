# Edge LB API v1

The management API has one public namespace: `/api/v1`. Unversioned `/api/...`
paths are rejected with HTTP 404 and are not alternate aliases.

## Resources

- `GET /api/v1/status`, `GET /api/v1/config`
- `GET|POST /api/v1/listener-configs`, `PUT|DELETE /api/v1/listener-configs/{name}`
- `GET|POST /api/v1/target-groups`, `PUT|DELETE /api/v1/target-groups/{name}`
- `GET|POST /api/v1/automations`, `PUT|DELETE /api/v1/automations/{name}`
- `GET|PUT /api/v1/notifications` and notification item operations
- `GET /api/v1/nodes/gateways`, `GET /api/v1/nodes/backends`
- `POST /api/v1/operations/{apply|cleanup|verify|failover}`

Import and export are subresources of their owning collection, for example
`/api/v1/listener-configs/export` and `/api/v1/target-groups/import`.

HA configuration and operations live under `/api/v1/ha`: `config`, `status`,
`pair`, `failover`, and `refresh-datapath`. Peer-only replication paths are
also under this namespace and require the paired peer bearer token.

`POST /api/v1/ha/peer/activate` is a peer-only operation used by coordinated
manual failover. The receiving gateway accepts the request only when the target
is itself, then binds the configured L2 VIP and announces it before replying.

The API returns edge-lb-native listener and target-group models. A target group
owns backend targets, weights, and optional health-check configuration. Runtime
health is included in the target-group view. There is no public standalone
backend-target resource: datapath entries are derived from target groups and
listeners.

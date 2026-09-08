# 实现约束与行为契约

本文档记录已经确认的实现语义。新增功能、问题修复和 UI 调整必须先更新本文档或对应的架构/API文档，再修改代码；不得为了临时解决问题引入未记录的数据模型或隐式回退。

## 1. 变更规则

- 监听配置和目标组是 edge-lb 自有模型，不映射成外部负载均衡器的业务对象。
- 监听配置只负责对外地址、对外端口、协议、调度策略、转发模式、目标组绑定和连接超时。
- 目标组只负责后端地址、权重和健康探测配置；监听配置负责目标转发端口。
- `Config.services` 和 `TargetEndpoint` 已删除；监听配置和目标组是唯一业务模型。
  native map 写入、DSCP 端口推导和回程端口推导都必须直接从
  `listeners + target_groups` 计算，不能重新引入运行期 service 投影。
- backend xDS 的 `backend_return_ports` 必须优先直接从 `listeners + target_groups`
  推导，不能下发监听、目标组或任何 gateway 业务配置字段。
- 自动配置模板只生成或覆盖目标组，字段名必须是 `target_group`；不接受
  `listener` 字段别名。
- 自动配置目标组在没有匹配节点时可以创建空目标组，方便监听提前绑定；但
  gateway 启动或 backend 重连的订阅稳定窗口内，不能用空匹配结果覆盖已有
  非空目标组，否则会短暂卸载 native DNAT 和 DSCP filter。
- 一个监听可以同时包含 TCP 和 UDP，但 API、持久化和 eBPF 规则中仍保持一个监听对象，不拆成两个业务监听。
- 监听未填写对外地址时，运行时使用本机 `underlay_ip`；启用二层 HA 时，L2 VIP 作为附加对外地址参与数据面规则。VIP 不通过 HA 配置同步到对端，主备只同步配置，VIP 由 L2 接管状态负责绑定和解绑。VIP 地址默认绑定到 `lo`，需要云网络或二层交换机直接看到 VIP 地址时才在 UI 高级配置中改为 `underlay` 或指定设备。
- gateway 节点列表中的 HA peer 必须使用配对时学习到的 peer `overlay_ip` 和
  `overlay_cidr`。peer overlay 允许属于对端网段，不能用本机 `gateway.overlay_ip`
  覆盖，也不能要求所有 `gateway_nodes[].overlay_ip` 都属于本机
  `network.overlay_cidr`。
- 后端只接收并执行数据面配置，不判断 active gateway，不保存 gateway 的 HA 运行来源。
- IPv4 forwarding 由 gateway 和 backend 启动时幂等开启：gateway 用于 DNAT 后转发，backend 用于容器、桥接地址或其他本地路由目标的回程转发；cleanup 不关闭这个主机级能力。

## Backend VXLAN reachability

VXLAN reachability is runtime kernel state and is reconciled during every
backend heal pass. The agent restores the managed device, local overlay
addresses, and configured gateway underlay peer FDB entries with netlink.
Learned entries are preserved and foreign entries are never removed. A
missing overlay neighbour is recovered by restoring the peer FDB and allowing
normal kernel neighbour resolution; gateway MAC addresses are not invented or
persisted by edge-lb.

Managed backend return tables may contain `/32` gateway-underlay bypass routes
via the backend underlay device with the local backend `src` address. These are
edge-lb-owned routes even if the current xDS snapshot only includes one gateway
inventory entry, and must not be reported as external `route_table` conflicts.
Ownership is keyed by the known gateway underlay destination plus `/32` route
shape; it must not depend solely on a transient device-name string such as
`auto`, `eth0`, `eth0(2)`, or a cloud NIC alias.
When a backend combines two gateway xDS streams, it must merge `gateway_nodes`
from every stream. Every per-gateway return table must include host routes for
all known gateway underlay IPs. A real failure on backend-b showed table
`1104` only had `192.168.0.12/32`; VXLAN packets for gateway
`192.168.0.16` then recursively followed the table default via `edge-return`,
so only hash selections landing on that backend timed out.
Backend xDS-derived config validation is role-aware: `gateway_nodes` and
`backend_nodes` may carry overlay addresses from multiple gateway CIDRs. Only
the snapshot network's own gateway overlay must belong to that snapshot CIDR;
peer gateway/backend overlays are inventory for route/FDB convergence, not
members of the current overlay.

## Recorded incident: VXLAN return path

When a backend generated a reply on `edge-return` but the client did not
receive it, inspection showed the policy route was correct while the runtime
overlay neighbour/FDB state was incomplete. Re-adding the managed peer FDB and
refreshing neighbour resolution restored the path. The backend heal loop now
performs this idempotently. During implementation, the compiler also caught a
temporary overlay-address borrow in the heal path; the fix keeps the local
backend binding alive while constructing the VXLAN specification.

## 2. 健康探测

健康探测只在目标组被监听配置引用且目标组开启探测时运行。关闭开关等价于 `probe_type = none`，不向用户暴露 `none` 选项。

支持的探测类型：

- `ping`：ICMP 探测，不使用端口、发送内容或响应匹配。
- `tcp`：建立 TCP 连接；可选发送内容和响应子串匹配。未配置响应匹配时，连接成功即健康。
- `udp`：发送可选内容；可选响应子串匹配。未配置响应匹配时，收到响应或在超时窗口内未收到 ICMP 不可达按当前 UDP 探测策略处理。
- `http`：使用探测路径发起 HTTP GET；默认按 `2xx/3xx` 健康，可选指定 HTTP 状态码和响应匹配。
- `https`：行为同 HTTP，可选跳过证书校验。

字段语义：

- `probe_port` 是健康探测端口，和监听的目标转发端口独立。
- `probe_req` 对 TCP/UDP 表示发送内容，对 HTTP/HTTPS 表示探测路径。
- `probe_resp` 表示响应内容子串匹配。
- `probe_status` 只适用于 HTTP/HTTPS，范围为 `100..=599`。
- `period_secs` 默认 15 秒，必须大于 0。
- `retries` 默认 3 次，失败达到阈值后标记不健康；成功恢复立即标记健康。
- 所有端口必须在 `1..=65535`；ping 不允许配置端口。
- UI、API normalization 和自动化模板必须保留 TCP/UDP 的 `probe_req` 与 `probe_resp`；只有关闭探测或选择 ping 时才清空这两个字段。

探测器使用可复用的 reqwest client 处理 HTTP/HTTPS。探测结果是观测状态，不修改目标组期望配置；状态变化才刷新数据面。

目标组 API 和 UI 的健康状态只展示三类：`ok`、`nok`、`unassociated`。
目标组未被任何监听引用时展示 `unassociated`；被监听引用后，缺失观测记录
或暂未收到探测结果都按 `nok` 展示，不能把 `unknown` 暴露给用户。

## 3. DSCP 统计

网关 DSCP TC 程序只记录：

- `matched`：IPv4 TCP/UDP 目标端口命中配置端口的包数。
- `changed`：命中后实际修改 DSCP 的包数。

不再记录 `seen` 和 `ipv4`。这两个计数需要在每包路径中额外更新，且不能提供必要的运维信号。native DNAT 的 stats 结构也移除了 `seen` 字段，只保留 `listener_hit`、`rewritten`、`return_miss`、`target_miss` 等能直接定位转发问题的计数。

## 4. 状态与生命周期

- 配置和业务对象持久化到 SQLite；运行时 eBPF map、连接流表和内核网络对象由 edge-lb 管理。
- native DNAT/SNAT 的连接状态源是 pinned eBPF `NATIVE_FLOWS`，不是 Linux
  内核 `nf_conntrack` 表。xSync 只能同步 native flow map 里的五元组和
  reverse-NAT value；`conntrack -L` 只能作为旁路诊断，不能作为 HA 同步、
  API 状态或正确性判断的依据。
- eBPF 程序由进程持有 link 生命周期；停止时只清理 edge-lb 自己创建的对象，不清理外部防火墙或其他程序对象。
- DSCP pinned map 的 ABI 变化必须在加载时检测；发现不匹配当前 ABI 的布局时自动重新挂载，不能静默按错误布局读取。
- reconcile 必须幂等：没有业务状态变化时不得反复 detach/attach eBPF、重写 SQLite 或重建路由。
- 数据库查询和稳定的 reconcile 细节使用 `debug`；`info` 只保留启动、状态变化、真正的配置变更和错误恢复。

## 5. 回归要求

涉及上述语义的修改至少覆盖：

- TCP/UDP 无 payload、带发送内容、带响应匹配三种探测路径。
- ping 不带端口，HTTP/HTTPS 状态码和 HTTPS 证书校验。
- 监听 TCP+UDP 单对象保存、读取和数据面应用。
- 目标组未绑定时不启动探测，绑定后能看到健康/不健康状态。
- 目标组健康列只能统计健康、不健康、未关联监听三类；关联监听后不能展示 `unknown`。
- DSCP 统计只输出 `matched` 和 `changed`。
- 重复 reconcile 不产生 attach churn、配置重复写入或孤立状态。
- gateway 的周期 heal 只检查 VXLAN 设备和 DSCP attachment；业务配置从 SQLite hydrate、native datapath reconcile 和 DSCP map 更新只在启动、配置版本变化或 attachment 丢失后执行。
- backend 的 xDS 长连接收到相同合并版本时只发送 ACK，不重复执行 VXLAN、FDB、策略路由、nft 和 native datapath apply；只有版本变化或首次收到版本时才应用配置。
- native 调度器支持 `rr`、`hash`、`priority`、`persist` 和 `lc`：`rr` 只在健康目标 slot 间轮询，不做权重展开；`hash` 使用内核 `bpf_get_hash_recalc(skb)` 的 skb hash 对目标 slot 取模；`priority` 按目标权重做加权轮询；`persist` 按客户端地址保持；`lc` 按活动 flow 数选择并轮转平局。未知选择器回退到 RR。`n2/n3` 不属于纯 TCP/UDP DNAT 数据面。
- native flow 命中任一方向时必须刷新正反两个 flow key 的 `last_seen_ns`，避免长连接单向活跃时另一方向提前过期；xSync 新建/删除走 ringbuf 事件，刷新状态通过低频差量 reconcile 同步，不做每包 refresh 事件。
- native xSync 验收必须以 `/api/v1/ha/status` 的 `xsync.state`、
  `xsync.last_error`、`xsync.last_ack_applied` 和 VIP 切主后的业务连通性为准；
  不能要求 Linux kernel conntrack 表出现同一条记录。
- HA/xSync 回归必须覆盖 A -> B 和 B -> A 两个方向的手动切主，并至少验证一条
  切主期间保持发送的 TCP 长连接不断；只验证新连接恢复不足以证明 native
  flow state 同步可接管。
- `lc` 的 active flow map 由 eBPF 在 flow 新建和显式删除时快速更新，同时由 gateway heal/xSync 兜底从 `NATIVE_FLOWS` 重算并删除过期 flow。不能只依赖 LRU map 被动淘汰，否则 active flow 计数不会自动回落。
- `hash` 模式才允许调用 `bpf_get_hash_recalc(skb)`；`rr`、`priority`、`persist`、`lc` 不应为 skb hash helper 付出额外新 flow 开销。

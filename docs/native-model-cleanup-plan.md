# Native 模型清理计划

## 目标

当前分支只支持 edge-lb 自研 native default DNAT/SNAT 数据面，不再保留
loxilb provider、旧 service 投影或不支持的监听模式字段。监听配置和目标组是
唯一业务模型：

- 监听配置：对外端口、协议、调度策略、目标组绑定、目标端口、连接空闲超时。
- 目标组：后端节点集合、权重、健康探测配置。
- native 数据面：从监听配置和目标组直接计算 listener lookup map、target map、
  flow map 和 xSync flow state。

## 执行项

1. 清理旧模型残留
   - 保持 `Config.services`、`Service`、`TargetEndpoint` 删除状态。
   - native 运行期对象、日志和局部变量使用 listener/target 语义。
   - `endpoint` 只允许用于通用网络连接 endpoint，例如 gRPC/HTTP endpoint；不能再表示
     目标组业务对象。

2. 删除 native 分支不支持的监听字段
   - 删除 per-listener `bgp`、`mark`、`security`、`host`、`proxy_protocol_v2`、
     `egress`。
   - 删除不支持的 `onearm/fullnat/dsr/fullproxy/hostonearm` 监听模式。
   - `mode` 固定为 `default`，UI/API 不再暴露其他转发模式。
   - HA 的 BGP、L2、hook 接管能力保留在 HA 配置中，不属于单个监听配置。

3. 保持 xDS/HA 边界
   - backend xDS 只下发回程所需的 gateway VXLAN、DSCP、mark/table 和端口信息。
   - HA 之间同步监听配置、目标组、自动目标组模板等业务对象，但不复制本机自动展开的
     VIP 地址。
   - xSync 只同步 native flow map 的连接状态。

4. 验证要求
   - `cargo fmt --all`
   - `make check`
   - `make ebpf`
   - `make clippy`
   - `make test`
   - `make ui`

## 非目标

- 本轮不新增 `n2/n3`、one-arm、fullnat 或 fullproxy 数据面。
- 本轮不修改 HA provider 的 BGP/L2/hook 表单能力。
- 本轮不做部署、打 tag 或提交，除非用户明确要求。

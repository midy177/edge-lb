# 文档索引

## 必读文档

- `architecture.md`：当前架构真相源，说明 gateway/backend/native datapath 职责、xDS、
  数据面、持久化和 HA 边界。
- `config.md`：当前配置真相源，说明 `/etc/edge-lb/config.toml`、角色配置、
  xDS 下发内容和管理 API。
- `api-v1.md`：当前管理 API 资源模型，只保留 `/api/v1` 路径。
- `native-resource-model.md`：当前业务资源模型，说明监听配置、目标组和运行态投影边界。
- `implementation-contracts.md`：已确认的监听、目标组、健康探测、DSCP 统计和生命周期
  语义。
- `vxlan-dscp-verified.md`：当前线上验证方案，记录已验证节点、VXLAN/DSCP
  参数、验证命令和排障检查。
- `ha-pressure-test-report.zh-CN.md` / `ha-pressure-test-report.md`：HA 和并发压测报告。

## 参考资料

当前仓库只保留 edge-lb native 数据面版本的文档。过期 provider、独立后端目标
API 和阶段计划文档已删除，不再作为实现依据。

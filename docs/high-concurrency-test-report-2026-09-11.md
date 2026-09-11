# edge-lb 高并发回归测试报告

测试日期：2026-09-11  
测试目标：验证 VIP `192.168.0.6:8080` 在高并发 TCP/UDP 访问下的转发稳定性、后端分布、健康检查与 eBPF 目标表状态。

## 结论

本轮高并发回归在 `concurrency=64` 下完成。TCP 在 3 秒超时阈值下达到 `100.00%` 成功率；UDP 在高压下仍有少量超时，3 秒阈值下成功率为 `99.99%`。压测结束后，两台 gateway 的 target group 均保持 `ok`，`NATIVE_TARGETS` 均为 `8` 个元素，两台 backend 服务均正常监听 TCP/UDP `8080`。

公网 UDP 探测 `43.128.39.211:8080` 已恢复响应，返回 backend `192.168.0.13`。

## 测试环境

| 角色 | 主机 | 地址 | 状态 |
| --- | --- | --- | --- |
| gateway-a | VM-0-12-ubuntu | `43.154.188.31` / `192.168.0.12` | `edge-lb 0.1.7`, active |
| gateway-b | VM-0-16-ubuntu | `129.226.226.55` / `192.168.0.16` | `edge-lb 0.1.7`, active |
| backend-a | VM-0-14-ubuntu | `192.168.0.14` | `edge-lb 0.1.7`, active |
| backend-b | VM-0-13-ubuntu | `43.162.213.70` / `192.168.0.13` | `edge-lb 0.1.7`, active |
| client | VM-0-10-ubuntu | `129.226.141.9` / `192.168.0.10` | `ha-bench` |

后端测试服务：

| 项 | 值 |
| --- | --- |
| 部署目录 | `/mnt/netdiscover` |
| 部署方式 | `nerdctl compose` |
| 镜像 | `docker.io/1228022817/netdiscover:v0.1.6` |
| 镜像 digest 前缀 | `9d4c2caa243c` |
| 监听 | TCP `0.0.0.0:8080`, UDP `0.0.0.0:8080` |

## 测试命令

### 低并发基线

```bash
ssh ubuntu@129.226.141.9 \
  '/usr/local/bin/ha-bench --target 192.168.0.6 --port 8080 \
  --protocol both --duration 30 --concurrency 16 \
  --payload discover --expect private_ipv4 --timeout-ms 1000 \
  --out /tmp/edge-lb-ha-vip-192.168.0.6-backend-server-image.tsv'
```

### 高并发，1 秒超时

```bash
ssh ubuntu@129.226.141.9 \
  '/usr/local/bin/ha-bench --target 192.168.0.6 --port 8080 \
  --protocol both --duration 60 --concurrency 64 \
  --payload discover --expect private_ipv4 --timeout-ms 1000 \
  --out /tmp/edge-lb-ha-vip-192.168.0.6-high-concurrency-c64.tsv'
```

### 高并发，3 秒超时对照

```bash
ssh ubuntu@129.226.141.9 \
  '/usr/local/bin/ha-bench --target 192.168.0.6 --port 8080 \
  --protocol both --duration 60 --concurrency 64 \
  --payload discover --expect private_ipv4 --timeout-ms 3000 \
  --out /tmp/edge-lb-ha-vip-192.168.0.6-high-concurrency-c64-timeout3000.tsv'
```

### 公网 UDP 探测

```bash
(printf 'discover\n'; sleep 1) | nc -uv -w 2 43.128.39.211 8080
```

## 测试结果

### 低并发基线，concurrency=16，timeout=1000ms

| 协议 | total | ok | fail | 成功率 | RPS | p50 | p95 | p99 | max |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| TCP | 262026 | 262026 | 0 | 100.00% | 8734.2 | 1.506ms | 3.528ms | 5.070ms | 23.278ms |
| UDP | 585065 | 585065 | 0 | 100.00% | 19502.2 | 0.485ms | 2.576ms | 4.360ms | 12.481ms |

后端分布：

| 协议 | `192.168.0.13` | `192.168.0.14` |
| --- | ---: | ---: |
| TCP | 132038 | 129988 |
| UDP | 395240 | 189825 |

### 高并发，concurrency=64，timeout=1000ms

| 协议 | total | ok | fail | 成功率 | RPS | p50 | p95 | p99 | max | 错误 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| TCP | 534536 | 534412 | 124 | 99.98% | 8908.9 | 5.537ms | 14.675ms | 19.542ms | 1010.833ms | timed out |
| UDP | 1872248 | 1871635 | 613 | 99.97% | 31204.1 | 0.869ms | 6.801ms | 10.487ms | 1063.422ms | timed out |

后端分布：

| 协议 | `192.168.0.13` | `192.168.0.14` |
| --- | ---: | ---: |
| TCP | 269353 | 265059 |
| UDP | 1543151 | 328484 |

### 高并发，concurrency=64，timeout=3000ms

| 协议 | total | ok | fail | 成功率 | RPS | p50 | p95 | p99 | max | 错误 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| TCP | 535684 | 535684 | 0 | 100.00% | 8928.1 | 5.489ms | 14.781ms | 18.796ms | 1078.452ms | 无 |
| UDP | 1851386 | 1851154 | 232 | 99.99% | 30856.4 | 0.887ms | 6.373ms | 9.471ms | 3061.538ms | timed out |

后端分布：

| 协议 | `192.168.0.13` | `192.168.0.14` |
| --- | ---: | ---: |
| TCP | 270272 | 265412 |
| UDP | 1481267 | 369887 |

### 公网 UDP 探测结果

```text
Connection to 43.128.39.211 port 8080 [udp/http-alt] succeeded!
{"hostname":"netdiscover-serve","private_ipv4":"192.168.0.13","public_ipv4":"43.162.213.70","public_ipv6":"","client_ip":"103.84.136.171","client_port":21623}
```

## 压测后状态

### Gateway 健康状态

两台 gateway 的 target group `8080` 均为 `ok`，两个 target 均为 `ok`：

```json
{
  "items": [
    {
      "name": "8080",
      "health": "ok",
      "targets": [
        { "backend": "VM-0-13-ubuntu", "address": "192.168.0.13", "health": "ok", "weight": 1 },
        { "backend": "VM-0-14-ubuntu", "address": "192.168.0.14", "health": "ok", "weight": 1 }
      ]
    }
  ],
  "page": 1,
  "per_page": 20,
  "total": 1
}
```

两台 gateway 的 eBPF target map 状态：

```text
NATIVE_TARGETS: Found 8 elements
```

### Backend 运行状态

两台 backend 的 `netdiscover-serve` 容器均为 `running`，镜像均为：

```text
docker.io/1228022817/netdiscover:v0.1.6
```

两台 backend 均监听：

```text
tcp LISTEN 0.0.0.0:8080
udp UNCONN 0.0.0.0:8080
```

## 观察与判断

1. TCP 高并发路径稳定。`concurrency=64` 下放宽到 3 秒超时后 0 失败，p99 约 `18.796ms`，说明正常延迟主体稳定，1 秒超时失败来自极少量尾延迟。
2. UDP 高并发路径可用但存在少量超时。`concurrency=64` 下 3 秒超时仍有 `232` 次 timeout，成功率 `99.99%`，需要在更长时间窗口或更高并发下继续观察是否与客户端发送速率、内核 UDP buffer、回程路径或单 active gateway 压力有关。
3. 控制面和健康面未出现异常。压测后 target group、target health、backend 容器、监听状态和 eBPF map 都保持正常。
4. UDP 后端分布不如 TCP 均匀。当前 `ha-bench` UDP 模式为 `reuse-per-worker`，源端口数量受 worker 数影响，分布会受到哈希输入影响；这不等同于真实大量客户端源端口的分布。

## 后续建议

1. 增加 `concurrency=128`、`duration=300s` 的长稳测试，分别记录 1 秒和 3 秒超时阈值结果。
2. 高并发 UDP 场景同时采集 `ss -su`、网卡丢包、softnet、nft counters 和 gateway eBPF stats，定位少量 timeout 的发生点。
3. 增加 UDP 多源端口或多客户端测试，降低 `reuse-per-worker` 对后端分布判断的影响。

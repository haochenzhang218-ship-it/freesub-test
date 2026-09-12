# 本地节点可用性验证报告

> 生成时间：2026-09-12 16:17:43  |  输入节点数：3  |  本机可用：0  |  不可用：3

## 详细结果

| # | 名称 | 协议 | 服务器 | 状态 | 失败阶段 | 详情 | 延迟 | 出口IP | 国家 |
|---|:---|:---|:---|:---|:---|:---|---:|:---|:---|
| 1 | 19d5a678 | vless | hinet1.2yly.com:24215 | FAIL | TCP | TCP FAIL: TimeoutError | 0ms | N/A | N/A |
| 2 | 36.224.152.189 | ss | 36.224.152.189:50099 | FAIL | TCP | TCP FAIL: TimeoutError | 0ms | N/A | N/A |
| 3 | r3mrcg001286ek2.cybe | ss | r3mrcg001286ek2.cybervena | FAIL | TCP | TCP FAIL: TimeoutError | 0ms | N/A | N/A |

## 说明

- **OK**：本机 TCP + TLS + Xray 代理 + 外网访问全部通过
- **TCP**：TCP 端口无法连接（服务器被封/关闭）
- **TLS**：TCP 通但 TLS 握手失败（Reality/TLS 参数错误）
- **XRAY**：xray 进程启动后立即退出（配置错误或内核问题）
- **PROXY**：代理建立成功但 ip-api.com 访问失败（节点限速/无流量）
# 📊 节点质量检测报告

> 生成时间：2026-09-12 06:15:39  |  检测节点总数：8  |  成功连通：8  |  失败：0

## 统计概览

| 等级 | 数量 |
|:---|---:|
| 🥇 优质家宽 | 3 |
| 🔴 数据中心 / Cloudflare / 不符合要求 | 5 |

## 详细结果

| # | 名称 | 协议 | 服务器 | 出口IP | 国家 | ASN | ISP/Org | IP类型 | 评级 | 延迟 |
|---|:---|:---|:---|:---|:---|:---|:---|:---|:---|---:|
| 1 | 19d5a678 | vless | hinet1.2yly.com:24215 | 118.167.209.5 | Taiwan | AS0 | Chunghwa Telecom Co., Ltd | 🥇 优质家宽 | 🥇 优质家宽 | 747ms |
| 2 | 77777777 | vless | 172.64.52.230:2087 | 104.28.160.83 | United States | AS0 | Cloudflare, Inc. | 🔴 数据中心 / 机房 | 🔴 数据中心 / Cloudflare / 不符合要求 | 59ms |
| 3 | 36.224.152.189 | ss | 36.224.152.189:50099 | 36.224.152.189 | Taiwan | AS0 | Chunghwa Telecom Co., Ltd | 🥇 优质家宽 | 🥇 优质家宽 | 450ms |
| 4 | 77777777 | vless | 172.64.52.230:2087 | 104.28.160.76 | United States | AS0 | Cloudflare, Inc. | 🔴 数据中心 / 机房 | 🔴 数据中心 / Cloudflare / 不符合要求 | 72ms |
| 5 | r3mrcg001286ek2.cybe | ss | r3mrcg001286ek2.cybervena.com:50099 | 36.224.174.174 | Taiwan | AS0 | Chunghwa Telecom Co., Ltd | 🥇 优质家宽 | 🥇 优质家宽 | 572ms |
| 6 | f2a73750 | vless | 162.159.153.4:443 | 104.28.167.115 | United States | AS0 | Cloudflare, Inc. | 🔴 数据中心 / 机房 | 🔴 数据中心 / Cloudflare / 不符合要求 | 42ms |
| 7 | 77777777 | vless | 104.16.150.108:2087 | 104.28.160.75 | United States | AS0 | Cloudflare, Inc. | 🔴 数据中心 / 机房 | 🔴 数据中心 / Cloudflare / 不符合要求 | 69ms |
| 8 | 47fcef29 | vless | 188.114.97.6:2052 | 104.28.161.183 | United States | AS0 | Cloudflare, Inc. | 🔴 数据中心 / 机房 | 🔴 数据中心 / Cloudflare / 不符合要求 | 54ms |

## 说明

- **🥇 优质家宽**：出口 IP 属于民用宽带 ASN，且命中住宅运营商白名单
- **🥈 优质 ISP / 原生 IP**：非数据中心 ASN，归属普通 ISP，可能为原生 IP
- **🟡 可用但普通**：可以连接但 IP 类型不明确
- **🔴 数据中心 / Cloudflare**：命中 Cloudflare CDN 网段或已知数据中心 ASN
- **⚫ 无法连接**：Xray 测活失败或超时

> ⚠️ 本报告基于实际代理出口 IP + ASN 数据库重新验证，与原始 `residential.txt` 的分类结果相互独立。
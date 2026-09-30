# doh-csv-worker

一个运行在 Cloudflare Worker 上的 DoH（DNS-over-HTTPS）服务：

- 支持自定义 DNS 记录：A / AAAA / CNAME / TXT / SRV / MX / CAA / NS / PTR / SOA
- 支持自定义 RCODE：NXDOMAIN / SERVFAIL / REFUSED
- 支持路由到上游：默认走 Cloudflare DoH，也支持按域名路由到其他 DoH 或 UDP DNS
- 配置使用 CSV（带表头），可直接放在 GitHub raw 文件里

## DoH 入口

- `POST /dns-query`（`content-type: application/dns-message`）
- `GET /dns-query?dns=<base64url>`（`application/dns-message`）

## WebUI

- `GET /`：查看配置摘要、测试解析（本地规则）

## CSV 配置格式

表头必须是：

```csv
name,type,ttl,data,rcode

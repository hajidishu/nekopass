# 传输协议

在「节点管理 → 编辑 → 编辑传输协议」分别选择传输协议和安全性。

| 传输协议 | 不加密 | TLS |
| --- | --- | --- |
| [raw(tcp)](./plain-tcp.md) | 每条转发连接使用一条明文 TCP 隧道 | 每条转发连接使用一条 TLS 隧道 |
| [raw(udp)](./raw-udp.md) | 原生 UDP，只承载 UDP 转发 | 使用 TLS 加密，只承载 UDP 转发 |
| [h2](./h2.md) | 明文 HTTP/2（h2c），多条转发连接共用连接池 | HTTP/2 over TLS，多条转发连接共用连接池 |

加密方式见 [安全性](../security/index.md)；证书、SNI、uTLS 等配置统一放在 [TLS](../security/tls.md) 页面。

旧「明文 TCP」对应 raw(tcp) + 不加密，旧「tls+h2」对应 h2 + TLS，升级后保持原组合。raw(tcp) + TLS 和 h2 + 不加密需要入口、出口都升级至 v0.15.0 或以上。

当前默认目标 IP 限制需要节点 v0.15.2 或以上，旧节点应先升级；详见 [转发安全](../guide/security.md)。

直转配置见 [TCP](./tcp.md) 和 [UDP](./udp.md)。

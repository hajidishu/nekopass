# DTLS

raw(udp) 的安全性选择「TLS」时实际使用 DTLS 数据报加密。raw(tcp) 与 h2 仍使用普通 TLS。

复用出口的证书域名、连接 SNI、信任根和证书模式，具体字段见 [TLS](./tls.md)。支持自签名、手动导入和 ACME 自动申请。DTLS 不使用现有 TCP uTLS 指纹选项。

节点间认证在 DTLS 握手前完成；无法通过认证的 UDP 探测不会收到握手回复。后续握手仍检查证书链和域名，不能使用错误证书。

DTLS 负责业务载荷加密，不承诺伪装成浏览器 HTTPS 或保证绕过网络封锁。原生 UDP 隧道没有网页 Fallback。

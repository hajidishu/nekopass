# 不加密

出口的「安全性」选择「不加密」，无需填写证书、SNI 或 uTLS 配置。

- 搭配 [raw(tcp)](../protocols/plain-tcp.md)：使用明文 TCP 隧道。
- 搭配 [h2](../protocols/h2.md)：使用明文 HTTP/2（h2c）。

隧道仍校验身份和规则权限，入口到出口的数据以明文传输。业务本身使用 HTTPS 等加密时，保留其原有加密。

此设置只影响入口到出口；节点到主控的 HTTP / HTTPS 连接单独配置。

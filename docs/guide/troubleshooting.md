# 常见问题

| 问题 | 检查 |
| --- | --- |
| 网页打不开 | `nekopassctl panel status`、`logs`；确认数据库、网页端口和云安全组 |
| 开机没有启动 | `systemctl is-enabled nekopass postgresql`；必要时 `systemctl enable --now postgresql nekopass` |
| 节点离线 | Agent 主控地址、对外端口、密钥、HTTP/HTTPS 连接方式和 `nekopassctl agent logs` |
| 节点自启但未运行 | `/etc/nekopass/agent.env` 是否存在且填写完整，再执行 `nekopassctl agent start` |
| 安装命令无法生成 | 系统设置的 Agent 主机、控制端口及安装脚本 / 版本下载源是否完整 |
| 用户选不到节点 | 节点已启用、允许入口、用户个人节点组授权；出口需关联入口 |
| 转发失败 | 节点同步、监听端口、目标可达性、个人有效期 / 额度和禁止目标网段 |
| TLS 中转失败 | 两端 Agent 版本、出口端口、证书有效期、SNI 与证书域名 |
| 节点在线但规则提示需升级 | 默认目标 IP 限制需要 v0.15.2 或以上节点，升级节点后重试 |
| 接收 PROXY Protocol 无法开启 | 管理员先在「系统设置 → 转发安全」填写可信来源 CIDR |
| HTTPS 节点提示未知 CA | 检查主控公共证书链和节点系统根证书；测试可使用明确的 HTTP 地址，隧道自签证书不是主控证书 |
| `error reading server preface: EOF` | 确认填写的是节点 gRPC 控制端口而非网页端口，HTTP / HTTPS 与实际监听一致 |
| 节点更新一直未确认 | 检查主控连接和节点更新日志，不能仅以等待状态判断升级成功 |
| 收不到注册邮件 | SMTP 地址、连接方式、授权码、发件邮箱及垃圾邮件目录；发送失败后等待冷却时间再试 |
| 已付款但充值未到账 | 检查网关通知能否访问面板公网地址、商户配置和待支付订单；返回页面不作为到账凭据 |
| 自动证书申请失败 | HTTP 模式检查公网 `80` 和域名解析；DNS 模式检查凭据与权限 |

实时日志：

```bash
sudo nekopassctl panel follow
sudo nekopassctl agent follow
```

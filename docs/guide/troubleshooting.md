# 常见问题

| 问题 | 检查 |
| --- | --- |
| 网页打不开 | `nekopassctl panel status`、`logs`；确认数据库、网页端口和云安全组 |
| 开机没有启动 | `systemctl is-enabled nekopass postgresql`；必要时 `systemctl enable --now postgresql nekopass` |
| 节点离线 | Agent 主控地址、对外端口、密钥、HTTP/HTTPS 连接方式和 `nekopassctl agent logs` |
| 节点自启但未运行 | `/etc/nekopass/agent.env` 是否存在且填写完整，再执行 `nekopassctl agent start` |
| 安装命令无法生成 | 系统设置的面板地址、Agent 地址及安装下载源是否完整 |
| 用户选不到节点 | 节点已启用、允许入口、所属组已获套餐授权；出口需关联入口 |
| 转发失败 | 节点同步、监听端口、目标可达性、套餐有效期和额度 |
| TLS 中转失败 | 两端 Agent 版本、出口端口、证书有效期、SNI 与证书域名 |
| 自动证书申请失败 | HTTP 模式检查公网 `80` 和域名解析；DNS 模式检查凭据与权限 |

实时日志：

```bash
sudo nekopassctl panel follow
sudo nekopassctl agent follow
```

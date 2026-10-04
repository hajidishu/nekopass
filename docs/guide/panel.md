# 安装面板

支持 Debian / Ubuntu、amd64 / arm64，使用原生 systemd。

## 本地安装包

将 `install-panel.sh` 与对应架构的安装包放在同一目录：

```bash
sudo bash install-panel.sh --package ./nekopass-panel-linux-amd64.tar.gz
```

ARM64 使用 `nekopass-panel-linux-arm64.tar.gz`。

## 网络安装

从 GitHub Releases 下载：

```bash
wget https://github.com/hajidishu/nekopass/releases/latest/download/install-panel.sh -O install-panel.sh && sudo bash install-panel.sh
```

安装完成后显示管理员账号与随机密码，并开启数据库、面板的开机自启。

| 默认入口 | 端口 |
| --- | --- |
| 网页 HTTP | `8080` |
| 节点控制连接 | `9443` |

打开 `http://服务器地址:8080`。云服务器还需放行安全组端口。

节点连接证书默认自动生成；网页 HTTPS 使用 [反向代理](./proxy.md)。

全部参数：`bash install-panel.sh --help`。忘记密码见 [日常管理](./manage.md#重置管理员密码)。

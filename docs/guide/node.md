# 安装节点

## 一键接入

在后台「节点管理」创建节点，复制该节点的「安装命令」，以 root 在节点服务器执行。

命令使用 `wget … -O nekopass-install-agent.sh && bash nekopass-install-agent.sh …`，参数直接包含面板地址、主控地址与端口、节点密钥、版本和下载源。节点地址使用 `https://`（公共 CA 可信证书）或测试用 `http://`（明文 HTTP/2），不附带 CA 参数。命令可重复使用。

节点显示「在线 / 已同步」后即可使用。端口范围、入口出口和探针设置均在后台修改。

## 下载配置

安装文件默认从 GitHub Releases 下载。在「系统设置」可修改下载配置：

| 设置 | 示例 |
| --- | --- |
| 安装脚本地址 | `https://github.com/hajidishu/nekopass/releases/latest/download/install-agent.sh` |
| 版本下载根地址 | `https://github.com/hajidishu/nekopass/releases/download` |
| Agent 版本 | `latest`（最新正式版，也可填写版本号） |

面板对外地址用于网页与安装接口；Agent 主控地址、端口用于节点连接，二者可以不同。

## 密钥与连接

节点密钥可在节点编辑中查看、修改，留空保存会生成新密钥。已安装节点更换密钥后，需要更新其连接配置并重启：

```bash
sudo nekopassctl agent configure
sudo nekopassctl agent restart
```

生产环境填写 `https://域名:端口`，证书由公共 CA 签发并覆盖该域名；测试环境填写 `http://IP:端口`。`NEKOPASS_SERVER` 未带协议的旧地址仍按 TLS 连接。

## 升级

在「节点管理」检查更新并点击节点的「更新」，或在节点执行：

```bash
sudo nekopassctl agent check-update
sudo nekopassctl agent update
```

老版本需先重新运行一次新版节点安装命令，以安装更新服务。更新会重启节点并中断现有连接。

保留 `/etc/nekopass/agent.env` 和 `/var/lib/nekopass-agent/state.db`；新服务器创建新节点。

## 动态 IP / DDNS

主控和 Agent 升级至 v0.9.0 后，在「节点管理」列表的操作栏点击「DDNS」，进入该节点的独立配置页。

首版支持 Cloudflare：填写记录域名、API Token，选择 IPv4 / IPv6 并保存。Token 需要对应区域的 **DNS 编辑**权限；Zone ID 留空时还需要 **Zone 读取**权限。

节点自动创建或更新 A / AAAA 记录，默认每 300 秒检查一次，采用仅 DNS 模式。可将域名用于节点公网地址和隧道出口地址；TLS 的 SNI、证书仍在原页面配置。

同步状态和「立即更新」均在 DDNS 页。停用后停止更新，已有 DNS 记录和节点地址保留。

# 安装节点

支持 Linux、amd64 / arm64，要求运行中的 systemd。

## 一键接入

在后台「节点管理」创建节点，复制该节点的「安装命令」，以 root 在节点服务器执行。

命令使用 `wget … -O nekopass-install-agent.sh && bash nekopass-install-agent.sh …`，参数直接包含主控 gRPC 地址与端口、节点密钥、版本和下载源。节点地址使用 `https://`（公共 CA 可信证书）或测试用 `http://`（明文 HTTP/2），不附带 CA 参数。命令可重复使用，自动判断首次安装或覆盖安装；传入的连接参数会覆盖配置文件，已有状态文件保留。

节点显示「在线 / 已同步」后即可使用。端口范围、入口出口和探针设置均在后台修改。

## 下载配置

安装文件默认从 GitHub Releases 下载。在「系统设置」可修改下载配置：

| 设置 | 示例 |
| --- | --- |
| 安装脚本地址 | `https://github.com/hajidishu/nekopass/releases/latest/download/install-agent.sh` |
| 版本下载根地址 | `https://github.com/hajidishu/nekopass/releases/download` |
| Agent 版本 | `latest`（最新正式版，也可填写版本号） |

节点连接信息由安装参数写入 `/etc/nekopass/agent.env`，只需 `NEKOPASS_SERVER` 和 `NEKOPASS_NODE_TOKEN`。规则、限速等运行配置通过 gRPC 下发；节点无需连接网页端口。

## 密钥与连接

节点密钥可在「节点管理 → 编辑」的基本信息中查看、复制和修改，留空保存会生成新密钥。已安装节点更换密钥后，需要更新其连接配置并重启：

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

老版本先重新运行新版节点安装命令，即可使用在线更新。

目标 IP 限制使用 v0.15.2 或以上节点；raw(udp) 中转使用 v0.17.1 或以上的面板及节点。

连接配置位于 `/etc/nekopass/agent.env`，运行状态位于 `/var/lib/nekopass-agent/state.db`。新增服务器时，在后台创建对应节点。

## 抢占实例重建

同一节点的服务器完全重建后，重新执行原安装命令即可接入。此功能使用 v0.16.1 或以上的面板及节点，每个节点对应一台服务器。

状态文件丢失时，节点使用原密钥获取主控保存的计数并恢复上线。历史已上报流量保留，旧节点尚未结算的有限流量授权按已消耗处理。

重新安装时，传入参数覆盖连接配置。更换密钥或主控地址会将原状态归档为 `state.db.before-reconfigure-*`；切换同一地址的 HTTP / HTTPS 会保留状态。

## 主控暂时离线

节点保留最后下发的配置并持续重连。有限额度用户只能使用该节点已获得的剩余授权，耗尽后等待主控恢复；无限额度用户仍受缓存权限和有效期限制。用量保存在状态文件中，恢复连接后继续上报。

## 动态 IP / DDNS

在节点列表点击「DDNS」，配置 Cloudflare、记录域名、IPv4 / IPv6 和同步参数。完整设置见 [节点与节点组](./nodes.md#ddns)。

## 入口、出口与传输协议

在「节点管理 → 编辑」中，点击「传输协议」旁的「编辑传输协议」，打开子窗口。关闭子窗口会返回节点编辑，保留未保存的基础信息。

入口和出口可同时启用。入口设置是否允许作为入口和是否允许直转。出口分别选择传输协议和安全性：raw(tcp)、h2 可搭配明文或 TLS；raw(udp) 仅用于 UDP，可搭配明文或 DTLS。uTLS 仅适用于 TLS，原生 UDP 不支持。Host、Path、Fallback 和流控仅用于 h2；入口统一使用所选出口的配置。UDP 配置见 [UDP 转发](../protocols/udp.md)。

出口配置始终显示。关闭「作为出口节点」时仍可编辑、保存参数和关联入口，但不开放隧道监听、不启动证书申请；启用后才生效。开关切换不会清空已填配置。

节点编辑保留基本信息、端口范围、连接限制和探针设置。已有节点的协议配置独立保存；添加节点时先在子窗口确定协议，再保存节点即可创建。

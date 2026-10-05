# Nekopass
>下列内容来自联合国世界人权宣言，gfw（中国防火长城）是对自由的侵犯，是对人权的亵渎，作为一个自由主义者，追求自由和维护人权是我的目标，因为任何人都应该有言论和思想的自由，此软件是为了维护自由和人权而开发的，这也是此软件没有卖200USD一年，而是完全开源免费的原因
>
>**序章**
>鉴于对人权的无视和侮蔑已发展为野蛮暴行，这些暴行玷污了人类的良心，而一个人人享有言论和信仰自由并免予恐惧和匮乏的世界的来临，已被宣布为普通人民的最高愿望
>
>**第一条**
>人人生而自由，在尊严和权利上一律平等。他们赋有理性和良心，并应以兄弟关系的精神相对待。
>
>**第二条**
>人人有资格享有本宣言所载的一切权利和自由，不分种族、肤色、性别、语言、宗教、政治或其他见解、国籍或社会出身、财产、出生或其他身分等任何区别。 并且不得因一人所属的国家或领土的政治的、行政的或者国际的地位之不同而有所区别，无论该领土是独立领土、托管领土、非自治领土或者处于其他任何主权受限制的情况之下。
>
>**第十二条**
>任何人的私生活、家庭、住宅和通信不得任意干涉，他的荣誉和名誉不得加以攻击。人人有权享受法律保护，以免受这种干涉或攻击。
>
>**第十九条**
>人人有权享有主张和发表意见的自由；此项权利包括持有主张而不受干涉的自由，和通过任何媒介和不论国界寻求、接受和传递消息和思想的自由

> *来源：[《联合国世界人权宣言》（简体中文）](https://www.un.org/zh/about-us/universal-declaration-of-human-rights)*

>为何要追求自由? **因为我们生而自由！** 为何要追求人权？ **因为我们同为人类！**

## 概述
Nekopass是一个开源免费的转发面板，设计参考了nyanpass，但是你不需要为nekopass支付一分钱，当然如果你乐意都话，欢迎捐款

### 核心特性

- 开源免费，采用 GPL-3.0 许可证。
- 支持多种加密隧道转发方式。
- uTLS模拟指纹，支持 Chrome、Firefox 等握手指纹。
- 基于h2的加密隧道，以及未认证访问的伪装网站fallback回退(防止主动探测)。
- 支持自签名、手动导入和 ACME 自动申请、续期证书。
- 套餐提供初始套餐资源配置，管理员可单独调整用户额度、已用流量、限速和权限。
- 支持带宽、IP、连接数和规则数量限制，以及不限资源、永不到期设置。
- 带宽按用户在各节点独立限速，流量按双向业务数据合计统计。
- 流量耗尽或套餐到期自动暂停转发，周期套餐支持每月重置流量。
- 支持余额购买、续费套餐、余额充值及订单和余额明细。
- 支持节点分组、入口与出口权限控制，节点配置无需手动编辑，由面板主控统一下发。
- 提供 CPU、内存、磁盘、实时网络速率、连接数和负载探针。
- 集成 DDNS功能，支持动态 IPv4、IPv6 地址更新。
- 支持转发规则分组、批量管理、负载均衡、Proxy Protocol 等特性
- 兼容 nyanpass导出的配置格式，转发规则可以从nyanpass无缝迁移
- 提供一键安装、CLI 服务管理，以及面板和节点在线更新。

## 安装面板

Debian / Ubuntu，amd64 / arm64：

```bash
wget https://github.com/hajidishu/nekopass/releases/latest/download/install-panel.sh -O install-panel.sh && sudo bash install-panel.sh
```

安装完成显示管理员账号和随机密码。网页默认 `8080`，节点控制端口 `9443`；网页 HTTPS 自行配置 Nginx。

## 安装节点

在后台「节点管理」复制安装命令，到节点服务器以 root 执行。

## 服务管理

交互菜单：`sudo nekopassctl`。`panel` 可替换为 `agent`：

```bash
sudo nekopassctl panel start        # 启动
sudo nekopassctl panel stop         # 停止
sudo nekopassctl panel restart      # 重启
sudo nekopassctl panel status       # 状态
sudo nekopassctl panel enable       # 开机自启
sudo nekopassctl panel disable      # 关闭自启
sudo nekopassctl panel logs         # 日志
sudo nekopassctl panel edit         # 编辑配置
sudo nekopassctl panel check-update # 检查更新
sudo nekopassctl panel update       # 更新
sudo nekopassctl agent configure    # 节点连接配置
sudo nekopassctl panel reset-password # 重置管理员密码
```

节点也可在后台「节点管理」更新。老版本节点需先重新执行一次新版安装命令，以安装更新服务。更新保留配置及状态，服务重启会中断现有连接。
## 文档

很显然readme.md放不下这么多字，所以我们创建了一个文档站，你可以在这里了解如何使用此软件

https://hajidishu.github.io/nekopass/

>文档由ai总结，目前缺少人工润色，但是不影响你查看

## 编译

需要 Go（版本见 `go.mod`）、Node.js 22.12+ 和 Python 3.9+。在项目根目录执行：

```bash
npm --prefix web ci
npm --prefix web run build
go build -o dist/bin/nekopass ./cmd/nekopass
go build -o dist/bin/nekopass-agent ./cmd/nekopass-agent
```

前端输出到 `web/dist/`，二进制输出到 `dist/bin/`，目标平台默认为当前系统。

打包 Linux amd64 / arm64 发布文件，需要 PowerShell 7，任选其一：

```bash
pwsh -File scripts/package-panel.ps1  # 面板和节点完整发布包
pwsh -File scripts/package-agent.ps1  # 仅节点发布文件
```

产物位于 `dist/oss/nekopass/`，可用 `-Version v0.14.2` 指定版本号。

## 如何贡献？

Fork 本仓库，新建分支，完成修改后向本仓库提交 PR。一个 PR 尽量只处理一个功能或问题，说明修改内容和验证结果。

>请不要提交ai大便，即使ai生成了一个看起来能跑的代码，你最好也得知道代码具体干了什么

提交前运行：

```bash
go test ./...
go vet ./...
npm --prefix web test
npm --prefix web run build
python scripts/check-public.py
```

数据库相关改动需将 `NEKOPASS_TEST_DATABASE_URL` 指向独立、名称以 `_test` 结尾的 PostgreSQL 测试库；未设置时数据库测试会跳过。文档站改动需额外执行 `npm --prefix docs ci` 和 `npm --prefix docs run build`。

不要提交运行配置、密钥、私钥、数据库或日志；`.local/`、`.tools/`、`dist/` 和 `node_modules/` 不属于源代码。

## 鸣谢
此软件的设计参考了多个开源项目：

[Xray-core](https://github.com/XTLS/Xray-core)nekopass的加密隧道实现参考了xray-core

[nyanpass](https://nyanpass.pages.dev/) nyanpass是一款很好的被广泛使用的加密隧道中转面板，但是很不幸，他并非自由软件，而是一个闭源且需要每年支付200$才可以使用的商业软件，所以才诞生出了nekopass

还需要感谢的是各种代理协议的设计者，本软件的加密隧道参考了多种代理协议的设计

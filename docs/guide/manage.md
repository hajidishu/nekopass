# 日常管理

## 服务命令

交互菜单：`sudo nekopassctl`。`panel` 可替换为 `agent`：

```bash
sudo nekopassctl panel start       # 启动
sudo nekopassctl panel stop        # 停止
sudo nekopassctl panel restart     # 重启
sudo nekopassctl panel status      # 状态
sudo nekopassctl panel enable      # 开机自启
sudo nekopassctl panel disable     # 关闭自启
sudo nekopassctl panel logs        # 最近日志
sudo nekopassctl panel follow      # 实时日志
sudo nekopassctl panel edit        # 编辑配置
sudo nekopassctl agent configure   # 节点连接配置
sudo nekopassctl panel check-update # 检查更新
sudo nekopassctl panel update       # 更新主控
```

修改配置后执行 `restart`。`enable` / `disable` 只更改自启。

## 重置管理员密码

```bash
sudo nekopassctl panel reset-password
```

命令显示新的随机密码，并注销该管理员的旧会话。

## 更新面板

使用 CLI 检查并更新；会自动下载 GitHub 发布包、升级数据库并重启服务：

```bash
sudo nekopassctl panel check-update
sudo nekopassctl panel update
```

更新前备份数据库和 `/etc/nekopass/`。节点升级见 [安装节点](./node.md#升级)。保留 `state.db`，不要复制给其他节点。

面板可在「管理后台 → 系统设置 → 立即更新」升级，页面会显示进度。后台与命令行共用 `nekopassctl panel update`；更新组件由安装和升级流程自动部署，无需额外配置。

若数据库迁移已开始而更新中断，更新器不会启动不兼容的旧程序；再次执行同版本或更新版本的更新命令可继续修复。

## 功能入口

| 功能 | 文档 |
| --- | --- |
| 注册、SMTP、条款和邀请返利 | [注册与邀请](./account.md) |
| 充值、购买和续费 | [商城与余额](./shop.md) |
| 用户、个人资源和套餐 | [用户与套餐](./users.md) |
| 节点、节点组、探针和 DDNS | [节点与节点组](./nodes.md) |
| 工单和客服对话 | [工单](./tickets.md) |
| 首页多公告 | [站点公告](./announcements.md) |
| 用户与管理员订单 | [订单查询](./orders.md) |
| 目标 IP 限制、PROXY 来源和管理密钥 | [转发安全](./security.md) |

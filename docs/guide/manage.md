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

面板可在「管理后台 → 系统设置 → 立即更新」升级，页面会显示进度。新安装默认已配置更新服务；旧安装升级到 v0.13.1 后，可运行一次 `sudo /opt/nekopass/bin/nekopass-update --service nekopass --setup-panel` 启用。

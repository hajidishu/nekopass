# Nekopass

TCP 端口转发面板，支持明文 / TLS 隧道，原生 systemd 部署。

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

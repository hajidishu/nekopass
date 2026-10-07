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

## 转发安全

「系统设置 → 转发安全」统一配置 PROXY Protocol 信任来源与禁止转发的目标 CIDR。默认禁止本机、内网及特殊用途地址，修改后自动下发节点；已有连接也会重新检查。PROXY 信任来源留空时禁止接收；目标禁止列表留空时允许全部目标。

启用目标禁止列表时，不支持该配置的旧节点会暂停转发，但保留在线状态和更新能力。升级节点后恢复转发。

## 注册与邮件

在「系统设置」填写 SMTP 主机、端口、连接方式、用户名/授权码和发件邮箱，再开启注册。人机验证可选择关闭或图形验证码；邮箱验证始终需要。注册后的电子邮件就是登录用户名。

## 邀请返利

在「系统设置」开启返利，设置首次/循环模式和比例；「用户管理 → 编辑」可单独覆盖或关闭。用户在「邀请返利」复制邀请码或链接，邀请链接会自动填入注册表单。

仅金额大于 0 的成功套餐购买和续费返利；充值和免费套餐不计算。首次模式只针对第一笔付费套餐订单。返利以分为单位计算，直接增加邀请人的余额，并出现在“我的订单”。

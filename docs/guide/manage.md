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

强制邀请默认关闭，须先开启邀请返利。启用后，新用户必须填写有效的老用户邀请码。用户条款和隐私条款 URL 可分别配置，注册页只显示已配置的链接，勾选同意仅在前端验证。

## 邀请返利

在「系统设置」开启返利，设置首次/循环模式和比例；「用户管理 → 编辑」可单独覆盖或关闭。用户在「邀请返利」复制邀请码或链接，邀请链接会自动填入注册表单。

仅金额大于 0 的成功套餐购买和续费返利；充值和免费套餐不计算。首次模式只针对第一笔付费套餐订单。返利以分为单位计算，直接增加邀请人的余额，并出现在“我的订单”。

## 工单与公告

用户在「工单」选择低、中、高优先级并提交纯文本问题，创建时使用系统配置的人机验证。管理员在「工单管理」回复、关闭或重新打开工单；优先级以淡蓝、淡黄、淡红区分。

「公告管理」支持多条公告、草稿和排序。首页每 8 秒轮播已发布公告，长正文显示摘要，点击「查看全文」展开。原有单条公告会自动保留。

## 订单查询

管理员在「订单查询」点击「筛选」，可组合订单号、用户邮箱/用户名、用户 ID、类型、状态、时间范围和支付平台流水号。时间可按创建时间或完成时间筛选，点击订单号查看详情。

「用户管理」中的「查询订单」会直接显示该用户的订单，账号改名后仍然有效。

#!/usr/bin/env bash
# Native systemd service manager. No application credentials are executed as shell code.
set -uo pipefail

usage() {
 cat <<'HELP'
Nekopass 服务管理（Linux / systemd）

  sudo nekopassctl                         打开交互菜单
  sudo nekopassctl panel                   管理面板端
  sudo nekopassctl agent                   管理节点端
  sudo nekopassctl agent start             启动服务
  sudo nekopassctl panel stop              停止服务
  sudo nekopassctl agent restart           重启服务
  sudo nekopassctl panel status            查看状态
  sudo nekopassctl agent enable            开启开机自启（不立即启动）
  sudo nekopassctl agent disable           关闭开机自启（不停止服务）
  sudo nekopassctl panel logs              最近 100 条日志
  sudo nekopassctl agent follow            实时日志，Ctrl+C 退出
  sudo nekopassctl agent edit              编辑连接配置，保存后手动重启
  sudo nekopassctl agent configure         填写主控 HTTP/HTTPS 地址和节点密钥
  sudo nekopassctl panel edit-service      编辑 systemd 服务覆盖配置
  sudo nekopassctl panel reset-password    重新生成管理员密码，并注销旧会话
  sudo nekopassctl agent check-update      检查 GitHub 最新版本（panel 也可用）
  sudo nekopassctl agent update            更新并重启服务，保留配置和状态

也支持指定独立节点服务：nekopassctl nekopass-agent-test status
这里的启动/停止/重启只作用于服务，不会重启或关闭服务器。
HELP
}
fail() { printf '错误：%s\n' "$*" >&2; return 1; }
select_service() {
 case "$1" in
  panel|control|nekopass) SERVICE=nekopass; CONFIG=/etc/nekopass/control.env; LABEL=面板端;;
  agent|nekopass-agent) SERVICE=nekopass-agent; CONFIG=/etc/nekopass/agent.env; LABEL=节点端;;
  nekopass-panel-*)
   [[ "$1" =~ ^nekopass-panel-[a-z0-9]{1,16}$ ]] || { fail '面板服务名不正确'; return 1; }
   SERVICE=$1; CONFIG="/etc/$SERVICE/control.env"; LABEL="面板端 ($SERVICE)";;
  *)
   [[ "$1" =~ ^nekopass-agent-[a-z0-9]{1,16}$ ]] || { fail '请选择 panel 或 agent'; return 1; }
   SERVICE=$1; CONFIG="/etc/$SERVICE/agent.env"; LABEL="节点端 ($SERVICE)";;
 esac
 [[ "$(systemctl show "$SERVICE.service" -p LoadState --value)" == loaded ]] || {
  fail "未安装服务 $SERVICE.service，请先安装对应服务。"; return 1;
 }
}
reset_password() {
 [[ "$CONFIG" == */control.env ]] || { fail '密码重置仅适用于面板端。'; return 1; }
 config_ready || return
 local username service_user binary
 printf '管理员账号（只有一个管理员时可留空）：'
 read -r username || return 1
 service_user=$(systemctl show "$SERVICE.service" -p User --value)
 [[ "$service_user" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || { fail '服务运行账户不正确。'; return 1; }
 binary="/opt/$SERVICE/bin/nekopass"
 [[ -x "$binary" ]] || { fail '面板程序不存在。'; return 1; }
 systemd-run --quiet --wait --pipe --collect -p "User=$service_user" -p "EnvironmentFile=$CONFIG" -- "$binary" -mode reset-admin -admin-name "$username"
}
config_ready() {
 [[ -s "$CONFIG" ]] || { fail "缺少配置 $CONFIG，请先选择编辑配置或填写节点连接信息。"; return 1; }
 if [[ "$CONFIG" == */agent.env ]]; then
  local key
  for key in NEKOPASS_SERVER NEKOPASS_NODE_TOKEN; do
   # Presence check only: never source an EnvironmentFile.
   awk -v key="$key" 'index($0,key "=")==1 { v=substr($0,length(key)+2); gsub(/^[[:space:]"\047]+|[[:space:]"\047]+$/, "", v); if(length(v)) ok=1 } END {exit !ok}' "$CONFIG" || {
    fail "$CONFIG 中的 $key 尚未填写。"; return 1;
   }
  done
 fi
}
backup_config() {
 [[ ! -f "$CONFIG" ]] || cp -p -- "$CONFIG" "$CONFIG.bak.$(date +%Y%m%d-%H%M%S).$$"
}
prepare_config() {
 [[ ! -L "$CONFIG" ]] || { fail '配置文件不能是符号链接。'; return 1; }
 install -d -m 755 "$(dirname "$CONFIG")" || return
 backup_config || return
 if [[ ! -f "$CONFIG" ]]; then
  [[ "$CONFIG" != */control.env ]] || { fail '面板配置缺失，请恢复数据库连接配置。'; return 1; }
  (umask 077; printf 'NEKOPASS_SERVER=\nNEKOPASS_NODE_TOKEN=\n' > "$CONFIG") || return
 fi
 chmod 600 "$CONFIG"
}
edit_config() {
 local -a editor_cmd
 if [[ -n "${EDITOR:-}" ]]; then
  read -r -a editor_cmd <<< "$EDITOR"
 elif command -v nano >/dev/null; then editor_cmd=(nano)
 elif command -v vi >/dev/null; then editor_cmd=(vi)
 else fail '请安装 nano/vi，或设置 EDITOR。'; return 1; fi
 command -v "${editor_cmd[0]}" >/dev/null || { fail '找不到 EDITOR 指定的编辑器。'; return 1; }
 prepare_config || return
 "${editor_cmd[@]}" "$CONFIG" || return
 chmod 600 "$CONFIG" || return
 printf '配置已保存。执行 nekopassctl %s restart 后生效。\n' "$SERVICE"
}
configure_agent() {
 [[ "$CONFIG" != */control.env ]] || { fail '此功能用于节点端，面板端请选择编辑配置。'; return 1; }
 local server token
 printf '主控地址（https://panel.example.com:9443 或测试用 http://IP:9443）：'
 read -r server || return 1
 python3 - "$server" <<'PY'
import sys,urllib.parse
raw=sys.argv[1];u=urllib.parse.urlsplit(raw if '://' in raw else '//'+raw)
try:port=u.port
except ValueError:sys.exit('主控端口无效')
if u.scheme not in ('','http','https') or not u.hostname or not port or not 1<=port<=65535 or u.path not in ('','/') or u.query or u.fragment or u.username or u.password or any(c in raw for c in '\r\n\0'):sys.exit('主控地址格式无效')
PY
 [[ $? -eq 0 ]] || return 1
 printf '节点密钥（从后台节点编辑中复制，输入不回显）：'
 read -rs token || return 1
 printf '\n'
 [[ "$token" =~ ^[A-Za-z0-9_-]{8,128}$ ]] || { fail '节点密钥格式不正确。'; return 1; }
 # Preserve other entries, including optional Agent settings. Do not touch state.db.
 prepare_config || return
 local tmp
 tmp=$(mktemp "$(dirname "$CONFIG")/.agent.env.XXXXXXXX") || return
 if ! {
  awk '!/^[[:space:]]*(NEKOPASS_SERVER|NEKOPASS_NODE_TOKEN|NEKOPASS_CA)=/' "$CONFIG" &&
  printf '\nNEKOPASS_SERVER=%s\nNEKOPASS_NODE_TOKEN=%s\n' "$server" "$token"
 } > "$tmp"; then rm -f -- "$tmp"; return 1; fi
 chmod 600 "$tmp" && mv -f -- "$tmp" "$CONFIG" || return
 printf '连接配置已保存。请确认密钥属于此机器原来的节点；状态文件和节点身份均保留。\n'
 printf '执行 nekopassctl %s restart 启动并应用配置。\n' "$SERVICE"
}
run_action() {
 case "$1" in
  start|restart)
   config_ready || return
   systemctl "$1" "$SERVICE.service" || return
   systemctl --no-pager --full status "$SERVICE.service";;
  stop) systemctl stop "$SERVICE.service";;
  status) systemctl --no-pager --full status "$SERVICE.service";;
  enable|disable) systemctl "$1" "$SERVICE.service";;
  logs) journalctl -u "$SERVICE.service" -n 100 --no-pager;;
  follow) journalctl -u "$SERVICE.service" -n 50 -f;;
  edit) edit_config;;
  configure) configure_agent;;
  reset-password) reset_password;;
  edit-service) systemctl edit "$SERVICE.service" && systemctl daemon-reload;;
  check-update|update)
   local base updater
   case "$SERVICE" in nekopass|nekopass-agent) base=/opt/nekopass;; *) base="/opt/$SERVICE";; esac
   updater="$base/bin/nekopass-update"
   [[ -x "$updater" ]] || { fail '请先使用新版安装脚本安装更新服务。'; return 1; }
   if [[ "$1" == check-update ]]; then "$updater" --service "$SERVICE" --check; else "$updater" --service "$SERVICE"; fi;;
  *) fail "未知操作：$1"; usage; return 1;;
 esac
}
service_menu() {
 local choice action
 while true; do
  printf '\nNekopass · %s\n' "$LABEL"
  printf '运行状态：%s  开机自启：%s\n配置：%s\n' "$(systemctl is-active "$SERVICE.service" 2>/dev/null)" "$(systemctl is-enabled "$SERVICE.service" 2>/dev/null)" "$CONFIG"
  printf '1 启动  2 停止  3 重启  4 查看状态\n5 开启自启  6 关闭自启  7 最近日志  8 实时日志\n9 编辑配置  10 填写节点连接信息  11 编辑服务配置\n'
  [[ "$CONFIG" != */control.env ]] || printf '12 重新生成管理员密码\n'
  printf '13 检查更新  14 更新到最新版本\n'
  printf '0 返回/退出\n请选择：'
  read -r choice || return 0
  case "$choice" in
   0) return 0;; 1) action=start;; 2) action=stop;; 3) action=restart;; 4) action=status;;
   5) action=enable;; 6) action=disable;; 7) action=logs;; 8) action=follow;;
   9) action=edit;; 10) action=configure;; 11) action=edit-service;;
   12) action=reset-password;;
   13) action=check-update;; 14) action=update;;
   *) printf '请输入菜单中的编号。\n'; continue;;
  esac
  # Ctrl+C leaves the current operation (e.g. live logs), keeping the menu usable.
  (trap - INT; run_action "$action") || printf '操作已结束，可查看日志了解服务情况。\n'
 done
}
case "${1:-}" in -h|--help|help) usage; exit 0;; esac
[[ $(id -u) -eq 0 ]] || { fail '请使用 sudo nekopassctl，或由 root 运行。'; exit 1; }
command -v systemctl >/dev/null && [[ -d /run/systemd/system ]] || { fail '需要运行 systemd 的 Linux 服务器。'; exit 1; }
[[ $# -le 2 ]] || { usage; exit 1; }
trap ':' INT
if (($#)); then
 select_service "$1" || exit 1
 if [[ $# -eq 2 ]]; then trap - INT; run_action "$2"; exit $?; fi
 service_menu; exit 0
fi
# The parent ignores Ctrl+C while a menu operation runs in its own subshell.
while true; do
 printf '\nNekopass 服务管理\n1 面板端  2 节点端  3 独立节点服务  0 退出\n请选择：'
 read -r choice || exit 0
 case "$choice" in
  0) exit 0;; 1) target=panel;; 2) target=agent;;
  3) systemctl list-unit-files 'nekopass-agent-*' --no-pager; printf '服务名（不含 .service）：'; read -r target || exit 0;;
  *) printf '请输入菜单中的编号。\n'; continue;;
 esac
 select_service "$target" && service_menu
done

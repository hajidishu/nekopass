#!/usr/bin/env bash
# Native Debian/Ubuntu installation. Web stays HTTP; TLS is for Agent control only.
set -Eeuo pipefail
umask 077
write_manager_payload() { return 1; }
# PACKAGED_MANAGER
write_updater_payload() { return 1; }
# PACKAGED_UPDATER
DEFAULT_DOWNLOAD_BASE='https://github.com/hajidishu/nekopass/releases/download'
RELEASE_VERSION='v0.12.0'; DOWNLOAD_BASE=$DEFAULT_DOWNLOAD_BASE; PACKAGE_URL=''; PACKAGE=''; SOURCE_DIR=''
SERVICE='nekopass'; HOST=''; AGENT_HOST=''; AGENT_PORT=''; HTTP_PORT=8080; GRPC_PORT=9443; DB_PORT=''; PG_VERSION=''
PG_SOURCE=system; ADMIN=admin; SITE=Nekopass; TLS_MODE=plain; TLS_CERT=''; TLS_KEY=''
AGENT_INSTALLER='https://github.com/hajidishu/nekopass/releases/latest/download/install-agent.sh'; AGENT_RELEASES='https://github.com/hajidishu/nekopass/releases/download'; FIREWALL=auto; YES=0; SKIP_DEPS=0; DRY_RUN=0; WORK=''
die() { printf '[nekopass] %s\n' "$*" >&2; exit 1; }
log() { printf '[nekopass] %s\n' "$*"; }
usage() {
 cat <<'HELP'
Nekopass 面板一键安装（Debian/Ubuntu，原生 systemd，以 root 执行）

  bash install-panel.sh                           交互式安装
  bash install-panel.sh --package /path/panel.tar.gz
  bash install-panel.sh --download-base https://github.com/hajidishu/nekopass/releases/download

  --package PATH           本地面板发布包
  --package-url URL        直接下载 HTTPS 发布包
  --download-base URL      HTTPS 版本下载根地址
  --source-dir PATH        已编译的源码目录（dist/bin + web/dist）
  --version VERSION        默认 v0.12.0
  --host HOST              用户/节点能访问的域名或 IP，不含协议
  --http-port PORT         网页 HTTP 端口，默认 8080
  --grpc-port PORT         节点连接端口，默认 9443
  --agent-host HOST        节点连接域名/IP，默认与面板相同
  --agent-port PORT        节点对外端口，默认与节点监听相同；代理模式默认 443
  --postgres-source NAME   system（系统源）或 pgdg（PostgreSQL 官方源）
  --postgres-version N     选择可用 PostgreSQL 主版本
  --db-port PORT           本机数据库端口，默认使用所选版本的现有集群
  --admin USER             初始管理员，默认 admin；密码随机生成
  --site-name NAME         站点名称
  --agent-tls MODE         plain（测试明文 HTTP/2）、existing（公共 CA 证书）、proxy（已有 TLS 反向代理）
  --tls-cert PATH          existing 模式的证书链
  --tls-key PATH           existing 模式的私钥
  --agent-installer URL    可选节点安装脚本 HTTPS 地址
  --agent-releases URL     可选节点版本下载根地址
  --firewall MODE          auto 自动放行活动的 UFW/firewalld；skip 跳过
  --service-name NAME      默认 nekopass，测试可用 nekopass-panel-xxx
  --yes                    使用参数和默认值，不询问
  --skip-dependencies      已具备依赖时跳过软件包安装
  --dry-run                只验证参数，不下载或修改机器
  -h, --help               显示帮助

安装完成：nekopassctl；忘记密码：nekopassctl panel reset-password
已有面板不会被覆盖；升级应保留配置及数据库。
HELP
}
value() { [[ $# -ge 2 && -n "$2" ]] || die "参数 $1 缺少值"; }
while (($#)); do
 case "$1" in
  -h|--help) usage; exit 0;;
  --package) value "$@"; PACKAGE=$2; shift 2;;
  --package-url) value "$@"; PACKAGE_URL=$2; shift 2;;
  --download-base) value "$@"; DOWNLOAD_BASE=${2%/}; shift 2;;
  --source-dir) value "$@"; SOURCE_DIR=$2; shift 2;;
  --version) value "$@"; RELEASE_VERSION=$2; shift 2;;
  --host) value "$@"; HOST=$2; shift 2;;
  --http-port) value "$@"; HTTP_PORT=$2; shift 2;;
  --grpc-port) value "$@"; GRPC_PORT=$2; shift 2;;
  --agent-host) value "$@"; AGENT_HOST=$2; shift 2;;
  --agent-port) value "$@"; AGENT_PORT=$2; shift 2;;
  --postgres-source) value "$@"; PG_SOURCE=$2; shift 2;;
  --postgres-version) value "$@"; PG_VERSION=$2; shift 2;;
  --db-port) value "$@"; DB_PORT=$2; shift 2;;
  --admin) value "$@"; ADMIN=$2; shift 2;;
  --site-name) value "$@"; SITE=$2; shift 2;;
  --agent-tls) value "$@"; TLS_MODE=$2; shift 2;;
  --tls-cert) value "$@"; TLS_CERT=$2; shift 2;;
  --tls-key) value "$@"; TLS_KEY=$2; shift 2;;
  --agent-installer) value "$@"; AGENT_INSTALLER=$2; shift 2;;
  --agent-releases) value "$@"; AGENT_RELEASES=$2; shift 2;;
  --firewall) value "$@"; FIREWALL=$2; shift 2;;
  --service-name) value "$@"; SERVICE=$2; shift 2;;
  --yes) YES=1; shift;;
  --skip-dependencies) SKIP_DEPS=1; shift;;
  --dry-run) DRY_RUN=1; shift;;
  *) die "未知参数：$1";;
 esac
done
[[ "$SERVICE" == nekopass || "$SERVICE" =~ ^nekopass-panel-[a-z0-9]{1,16}$ ]] || die '服务名不正确'
[[ "$RELEASE_VERSION" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ && "$RELEASE_VERSION" != *..* ]] || die '版本格式不正确'
case "$(uname -m)" in x86_64|amd64) ARCH=amd64;; aarch64|arm64) ARCH=arm64;; *) die '只支持 amd64 / arm64';; esac
[[ "$(uname -s)" == Linux ]] || die '需要 Linux'
port_ok() { [[ "$1" =~ ^[0-9]{1,5}$ ]] && ((10#$1 >= 1 && 10#$1 <= 65535)); }
port_ok "$HTTP_PORT" && port_ok "$GRPC_PORT" || die '端口须为 1–65535'
[[ "$HTTP_PORT" != "$GRPC_PORT" ]] || die '网页和节点连接端口不能相同'
[[ -z "$DB_PORT" ]] || port_ok "$DB_PORT" || die '数据库端口不正确'
[[ -z "$AGENT_PORT" ]] || port_ok "$AGENT_PORT" || die '节点对外端口不正确'
[[ -z "$PG_VERSION" || "$PG_VERSION" =~ ^[0-9]{2}$ ]] || die '数据库主版本不正确'
[[ "$PG_SOURCE" == system || "$PG_SOURCE" == pgdg ]] || die '数据库来源不正确'
[[ "$TLS_MODE" == plain || "$TLS_MODE" == existing || "$TLS_MODE" == proxy ]] || die '节点 TLS 模式不正确'
[[ "$FIREWALL" == auto || "$FIREWALL" == skip ]] || die '防火墙模式不正确'
if ((DRY_RUN)); then log "计划：linux/$ARCH，服务 $SERVICE，网页 $HTTP_PORT，节点 $GRPC_PORT，数据库 $PG_SOURCE/${PG_VERSION:-默认}，版本 $RELEASE_VERSION"; exit 0; fi
[[ $(id -u) -eq 0 ]] || die '请以 root 执行'
[[ -d /run/systemd/system ]] && command -v systemctl >/dev/null || die '需要正在运行的 systemd'
. /etc/os-release
[[ "$ID" == debian || "$ID" == ubuntu ]] || die '当前安装器支持 Debian / Ubuntu'
BASE="/opt/$SERVICE"; CONFIG="/etc/$SERVICE"; [[ "$SERVICE" != nekopass ]] || CONFIG=/etc/nekopass
UNIT="/etc/systemd/system/$SERVICE.service"
[[ ! -e "$CONFIG/control.env" && ! -e "$UNIT" && ! -e "$BASE/bin/nekopass" ]] || die '此服务已有安装，请使用 nekopassctl 管理或按升级方式更新，安装器不会覆盖它'
for target in "$BASE" "$CONFIG" "$UNIT" /usr/local/bin/nekopassctl; do
 [[ ! -L "$target" && "$(realpath -m "$target")" == "$target" ]] || die '安装目标不能是符号链接';
done
prompt() {
 local key=$1 label=$2 default=$3 answer
 if ((YES)); then printf -v "$key" '%s' "$default"; return; fi
 # Readline handles cursor keys, Home/End, Delete and Backspace. Keep the
 # default in the editable buffer, including when the script uses piped stdin.
 if [[ -t 0 ]]; then
  read -r -e -i "$default" -p "$label [$default]：" answer || die '交互输入已结束'
 else
  read -r -e -i "$default" -p "$label [$default]：" answer </dev/tty || die '无法交互，请使用 --yes 并提供参数'
 fi
 printf -v "$key" '%s' "${answer:-$default}"
}
log '请选择安装配置；回车使用默认值，可用方向键和删除键编辑。'
detected=$(hostname -I 2>/dev/null | awk '{print $1}')
prompt HOST '面板/节点可访问的域名或 IP' "${HOST:-${detected:-127.0.0.1}}"
prompt HTTP_PORT '面板 HTTP 端口' "$HTTP_PORT"
prompt GRPC_PORT '节点控制端口' "$GRPC_PORT"
prompt ADMIN '管理员账号' "$ADMIN"
prompt SITE '站点名称' "$SITE"
prompt PG_SOURCE '数据库来源（system 系统源 / pgdg 官方源）' "$PG_SOURCE"
prompt TLS_MODE '节点连接（plain 测试明文 / existing 公共证书 / proxy 已有 TLS 代理）' "$TLS_MODE"
AGENT_HOST=${AGENT_HOST:-$HOST}
if [[ "$TLS_MODE" == proxy ]]; then
 prompt AGENT_HOST '现有代理的节点连接域名/IP' "$AGENT_HOST"
 prompt AGENT_PORT '现有代理的节点对外端口' "${AGENT_PORT:-443}"
else AGENT_PORT=${AGENT_PORT:-$GRPC_PORT}; fi
if [[ "$TLS_MODE" == existing ]]; then
 prompt TLS_CERT '已有证书链绝对路径' "$TLS_CERT"
 prompt TLS_KEY '已有私钥绝对路径' "$TLS_KEY"
fi
port_ok "$HTTP_PORT" && port_ok "$GRPC_PORT" && [[ "$HTTP_PORT" != "$GRPC_PORT" ]] || die '网页和节点端口须有效且不同'
port_ok "$AGENT_PORT" || die '节点对外端口不正确'
[[ "$PG_SOURCE" == system || "$PG_SOURCE" == pgdg ]] || die '数据库来源不正确'
[[ "$TLS_MODE" == plain || "$TLS_MODE" == existing || "$TLS_MODE" == proxy ]] || die '节点连接方式不正确'
export DEBIAN_FRONTEND=noninteractive
if ((!SKIP_DEPS)); then
 apt-get update
 apt-get install -y curl ca-certificates python3 openssl postgresql-common
fi
for cmd in curl python3 openssl pg_lsclusters pg_createcluster systemd-run; do command -v "$cmd" >/dev/null || die "缺少依赖：$cmd"; done
python3 - "$HOST" "$AGENT_HOST" "$ADMIN" "$SITE" <<'PY'
import ipaddress,re,sys
host,agent,admin,site=sys.argv[1:]
for name in [host,agent]:
 try:ipaddress.ip_address(name)
 except ValueError:
  if len(name)>253 or not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?',label) for label in name.split('.')):sys.exit('域名或 IP 不正确，不含协议、路径或端口')
if not admin or len(admin.encode())>64 or any(c in admin for c in '\r\n\0'):sys.exit('管理员账号不正确')
if not site.strip() or len(site)>64 or any(c in site for c in '\r\n\0'):sys.exit('站点名称不正确')
PY
WORK=$(mktemp -d /var/tmp/nekopass-panel-install.XXXXXXXX)
cleanup() {
 local status=$?
 if ((status)); then log "安装未完成，已有数据不会删除。查看：journalctl -u $SERVICE -n 50 --no-pager"; fi
 [[ -z "$WORK" || "$WORK" != /var/tmp/nekopass-panel-install.* ]] || rm -rf -- "$WORK"
}
trap cleanup EXIT
fetch() {
 python3 - "$1" <<'PY'
import sys,urllib.parse
v=urllib.parse.urlsplit(sys.argv[1])
if v.scheme!='https' or not v.hostname or v.username or v.password or v.fragment or any(c in sys.argv[1] for c in '\r\n\0'):sys.exit('下载地址必须为 HTTPS')
PY
 curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 600 --retry 3 "$1" -o "$2"
}
if [[ -z "$PACKAGE" && -z "$PACKAGE_URL" && -z "$DOWNLOAD_BASE" && -z "$SOURCE_DIR" ]]; then
 repo="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
 if [[ -f "$repo/dist/bin/nekopass" && -d "$repo/web/dist/pages" ]]; then SOURCE_DIR=$repo
 else prompt DOWNLOAD_BASE '面板版本下载根地址（HTTPS）' ''; fi
fi
if [[ -n "$SOURCE_DIR" ]]; then
 [[ -z "$PACKAGE" && -z "$PACKAGE_URL" ]] || die '源码目录与发布包不能同时使用'
 install -d "$WORK/release/bin" "$WORK/release/web"
 cp "$SOURCE_DIR/dist/bin/nekopass" "$WORK/release/bin/nekopass"
 cp -r "$SOURCE_DIR/web/dist/." "$WORK/release/web/"
 if [[ -f "$SOURCE_DIR/dist/bin/nekopassctl" ]]; then cp "$SOURCE_DIR/dist/bin/nekopassctl" "$WORK/release/bin/nekopassctl"; fi
else
 if [[ -z "$PACKAGE" ]]; then
  [[ -n "$PACKAGE_URL" ]] || PACKAGE_URL="$DOWNLOAD_BASE/$RELEASE_VERSION/nekopass-panel-linux-$ARCH.tar.gz"
  log '下载面板安装包'
  fetch "$PACKAGE_URL" "$WORK/panel.tar.gz"; PACKAGE="$WORK/panel.tar.gz"
 fi
 python3 - "$PACKAGE" "$WORK/release" <<'PY'
import pathlib,sys,tarfile
root=pathlib.Path(sys.argv[2]);root.mkdir()
with tarfile.open(sys.argv[1],'r:gz') as archive:
 members=archive.getmembers()
 if len(members)>20000 or sum(max(0,m.size) for m in members)>1024**3:sys.exit('安装包过大')
 for m in members:
  name=pathlib.PurePosixPath(m.name)
  if name.is_absolute() or '..' in name.parts or not name.parts or name.parts[0] not in {'bin','web','LICENSE'} or not (m.isfile() or m.isdir()):sys.exit('安装包路径不安全')
  if any(c in m.name for c in '\r\n\0\\'):sys.exit('安装包路径不正确')
 archive.extractall(root,filter='data') if sys.version_info>=(3,12) else archive.extractall(root)
PY
fi
[[ -f "$WORK/release/bin/nekopass" && -d "$WORK/release/web/pages" && -d "$WORK/release/web/assets" ]] || die '安装包缺少面板程序或完整网页'
chmod 700 "$WORK/release/bin/nekopass"
"$WORK/release/bin/nekopass" -h >/dev/null 2>&1 || die '面板程序无法在当前机器运行'
if ! write_manager_payload > "$WORK/nekopassctl"; then
 if [[ -f "$WORK/release/bin/nekopassctl" ]]; then cp "$WORK/release/bin/nekopassctl" "$WORK/nekopassctl"
 else companion="$(dirname -- "${BASH_SOURCE[0]}")/nekopassctl.sh"; [[ -f "$companion" ]] || die '缺少服务管理工具，请使用完整发布安装脚本'; tr -d '\r' < "$companion" > "$WORK/nekopassctl"; fi
fi
bash -n "$WORK/nekopassctl"
if ! write_updater_payload > "$WORK/nekopass-update"; then
 if [[ -f "$WORK/release/bin/nekopass-update" ]]; then cp "$WORK/release/bin/nekopass-update" "$WORK/nekopass-update"
 else companion="$(dirname -- "${BASH_SOURCE[0]}")/nekopass-update.py"; [[ -f "$companion" ]] || die '缺少更新工具，请使用完整发布安装脚本'; cp "$companion" "$WORK/nekopass-update"; fi
fi
python3 - "$HTTP_PORT" "$GRPC_PORT" "$TLS_MODE" <<'PY'
import socket,sys
for address,port in [('0.0.0.0',sys.argv[1]),('127.0.0.1' if sys.argv[3]=='proxy' else '0.0.0.0',sys.argv[2])]:
 with socket.socket() as sock:
  sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
  try:sock.bind((address,int(port)))
  except OSError:sys.exit('端口 '+port+' 已被占用，请选择其他端口')
PY
if [[ "$PG_SOURCE" == pgdg && $SKIP_DEPS == 0 ]]; then
 [[ "$VERSION_CODENAME" =~ ^[a-z]+$ ]] || die '系统发行代号不正确'
 # PostgreSQL official repository instructions: https://www.postgresql.org/download/linux/debian/
 fetch https://www.postgresql.org/media/keys/ACCC4CF8.asc "$WORK/pgdg.asc"
 install -d /usr/share/postgresql-common/pgdg
 install -m 644 "$WORK/pgdg.asc" /usr/share/postgresql-common/pgdg/nekopass.asc
 printf 'Types: deb\nURIs: https://apt.postgresql.org/pub/repos/apt\nSuites: %s-pgdg\nArchitectures: %s\nComponents: main\nSigned-By: /usr/share/postgresql-common/pgdg/nekopass.asc\n' "$VERSION_CODENAME" "$ARCH" > /etc/apt/sources.list.d/nekopass-pgdg.sources
 chmod 644 /etc/apt/sources.list.d/nekopass-pgdg.sources
 apt-get update
fi
available=$(apt-cache search --names-only '^postgresql-[0-9]+$' | awk '{sub("postgresql-", "", $1); if($1>=14) print $1}' | sort -n | tr '\n' ' ')
[[ -n "$available" ]] || die '软件源没有 PostgreSQL 14 或以上版本'
log "可用 PostgreSQL 版本：$available"
default_pg=$(pg_lsclusters --no-header | awk '$4=="online" {print $1;exit}')
[[ " $available " == *" ${default_pg:-none} "* ]] || default_pg=$(awk '{print $NF}' <<< "$available")
prompt PG_VERSION 'PostgreSQL 主版本' "${PG_VERSION:-$default_pg}"
[[ "$PG_VERSION" =~ ^[0-9]{2}$ && " $available " == *" $PG_VERSION "* ]] || die '选择的数据库版本不在可用列表中'
if ((!SKIP_DEPS)); then apt-get install -y "postgresql-$PG_VERSION"; fi
[[ -x "/usr/lib/postgresql/$PG_VERSION/bin/postgres" ]] || die '所选数据库版本尚未安装'
default_db=$(pg_lsclusters --no-header | awk -v v="$PG_VERSION" '$1==v {print $3;exit}')
if [[ -z "$default_db" ]]; then
 default_db=5432
 while pg_lsclusters --no-header | awk -v p="$default_db" '$3==p {found=1} END {exit !found}'; do default_db=$((default_db+1)); done
fi
prompt DB_PORT '本机数据库端口' "${DB_PORT:-$default_db}"
port_ok "$DB_PORT" || die '数据库端口不正确'
cluster=$(pg_lsclusters --no-header | awk -v v="$PG_VERSION" -v p="$DB_PORT" '$1==v && $3==p {print $2;exit}')
if [[ -z "$cluster" ]]; then
 if pg_lsclusters --no-header | awk -v p="$DB_PORT" '$3==p {found=1} END {exit !found}'; then die '该端口属于另一个 PostgreSQL 版本'; fi
 pg_createcluster "$PG_VERSION" "$SERVICE" --port "$DB_PORT" --start
 cluster=$SERVICE
else
 pg_ctlcluster "$PG_VERSION" "$cluster" start || pg_isready -p "$DB_PORT" >/dev/null
fi
systemctl enable postgresql >/dev/null
systemctl enable "postgresql@$PG_VERSION-$cluster" >/dev/null
existing=$(runuser -u postgres -- psql -p "$DB_PORT" -XAtqc "SELECT count(*) FROM pg_database WHERE datname='$SERVICE'")
[[ "$existing" == 0 ]] || die '同名数据库已存在，不会覆盖；请使用其他服务名或恢复原安装'
id "$SERVICE" >/dev/null 2>&1 || useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin "$SERVICE"
role=$(runuser -u postgres -- psql -p "$DB_PORT" -XAtqc "SELECT count(*) FROM pg_roles WHERE rolname='$SERVICE'")
[[ "$role" == 0 ]] || die '同名数据库角色已存在，安装器不会修改现有角色'
runuser -u postgres -- createuser -p "$DB_PORT" "$SERVICE"
runuser -u postgres -- createdb -p "$DB_PORT" -O "$SERVICE" "$SERVICE"
install -d -m 755 "$BASE/bin" "$BASE/web" "$CONFIG"
install -m 755 "$WORK/release/bin/nekopass" "$BASE/bin/nekopass"
cp -r "$WORK/release/web/." "$BASE/web/"
# Installation is private by default; published web files must be readable by the service.
find "$BASE/web" -type d -exec chmod 755 {} +
find "$BASE/web" -type f -exec chmod 644 {} +
python3 - "$SERVICE" "$DB_PORT" "$WORK/control.env" <<'PY'
import pathlib,sys,urllib.parse
name,port,path=sys.argv[1:]
dsn='postgres://'+urllib.parse.quote(name,safe='')+'@/'+urllib.parse.quote(name,safe='')+'?host=/var/run/postgresql&port='+port+'&sslmode=disable'
pathlib.Path(path).write_text('NEKOPASS_DATABASE_URL='+dsn+'\nNEKOPASS_TRUSTED_PROXIES=127.0.0.0/8,::1/128\n')
PY
GRPC_BIND=0.0.0.0
if [[ "$TLS_MODE" == existing ]]; then
 [[ -f "$TLS_CERT" && -f "$TLS_KEY" ]] || die '节点连接证书或私钥不存在'
 openssl x509 -in "$TLS_CERT" -checkend 0 -noout >/dev/null || die '证书已过期或无效'
 openssl verify -untrusted "$TLS_CERT" "$TLS_CERT" >/dev/null || die '节点连接需要系统信任的公共 CA 证书链'
 openssl x509 -in "$TLS_CERT" -pubkey -noout > "$WORK/cert-public"
 openssl pkey -in "$TLS_KEY" -pubout > "$WORK/key-public" 2>/dev/null
 cmp -s "$WORK/cert-public" "$WORK/key-public" || die '证书与私钥不匹配'
 if python3 - "$AGENT_HOST" <<'PY'
import ipaddress,sys
try:ipaddress.ip_address(sys.argv[1])
except ValueError:sys.exit(1)
PY
 then openssl x509 -in "$TLS_CERT" -checkip "$AGENT_HOST" -noout >/dev/null || die '证书未包含连接 IP'
 else openssl x509 -in "$TLS_CERT" -checkhost "$AGENT_HOST" -noout >/dev/null || die '证书未包含连接域名'; fi
 install -d -m 750 -g "$SERVICE" "$CONFIG/tls"
 install -m 644 "$TLS_CERT" "$CONFIG/tls/server.crt"
 install -m 640 -g "$SERVICE" "$TLS_KEY" "$CONFIG/tls/server.key"
 printf 'NEKOPASS_GRPC_TLS_CERT=%s/tls/server.crt\nNEKOPASS_GRPC_TLS_KEY=%s/tls/server.key\n' "$CONFIG" "$CONFIG" >> "$WORK/control.env"
elif [[ "$TLS_MODE" == proxy ]]; then GRPC_BIND=127.0.0.1
else GRPC_BIND=0.0.0.0; fi
install -m 600 "$WORK/control.env" "$CONFIG/control.env"
cat > "$WORK/panel.service" <<UNIT
[Unit]
Description=Nekopass control panel
After=network-online.target postgresql@$PG_VERSION-$cluster.service
Wants=network-online.target
Requires=postgresql@$PG_VERSION-$cluster.service
[Service]
Type=simple
User=$SERVICE
Group=$SERVICE
EnvironmentFile=$CONFIG/control.env
ExecStart=$BASE/bin/nekopass -web $BASE/web -http :$HTTP_PORT -grpc $GRPC_BIND:$GRPC_PORT
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
UNIT
install -m 644 "$WORK/panel.service" "$UNIT"
install -d -m 755 /usr/local/bin
install -m 755 "$WORK/nekopassctl" /usr/local/bin/nekopassctl
install -m 755 "$WORK/nekopass-update" "$BASE/bin/nekopass-update"
run_panel() { systemd-run --quiet --wait --pipe --collect -p "User=$SERVICE" -p "EnvironmentFile=$CONFIG/control.env" -- "$BASE/bin/nekopass" "$@"; }
run_panel -mode migrate
if [[ -n "$DOWNLOAD_BASE" && -z "$AGENT_RELEASES" ]]; then AGENT_RELEASES=$DOWNLOAD_BASE; fi
if [[ -n "$DOWNLOAD_BASE" && -z "$AGENT_INSTALLER" ]]; then AGENT_INSTALLER="${DOWNLOAD_BASE%/releases}/install-agent.sh"; fi
prompt AGENT_INSTALLER '可选节点安装脚本 HTTPS 地址（无下载源可留空）' "$AGENT_INSTALLER"
prompt AGENT_RELEASES '可选节点版本下载根地址（无下载源可留空）' "$AGENT_RELEASES"
python3 - "$HOST" "$HTTP_PORT" "$AGENT_HOST" "$AGENT_PORT" "$SITE" "$AGENT_INSTALLER" "$AGENT_RELEASES" "$RELEASE_VERSION" "$TLS_MODE" > "$WORK/settings.json" <<'PY'
import json,sys
host,http,agent,grpc,site,installer,releases,version,transport=sys.argv[1:]
authority='['+host+']' if ':' in host else host
print(json.dumps(dict(site_name=site,panel_url='http://'+authority+':'+http,agent_host=agent,agent_port=int(grpc),agent_transport='plain' if transport=='plain' else 'tls',installer_url=installer,release_base_url=releases,agent_version='latest',install_token_minutes=30)))
PY
run_panel -mode init-settings < "$WORK/settings.json"
log '创建管理员并随机生成密码'
run_panel -mode bootstrap -random-password -admin-name "$ADMIN" > "$WORK/admin-result"
systemctl daemon-reload
systemctl enable --now "$SERVICE" >/dev/null
ready=0
for ((i=0;i<30;i++)); do if curl --fail --silent "http://127.0.0.1:$HTTP_PORT/healthz" >/dev/null; then ready=1; break; fi; sleep 1; done
((ready)) && systemctl is-active --quiet "$SERVICE" || die '面板未能正常启动，请查看日志'
if [[ "$FIREWALL" == auto ]]; then
 ports=("$HTTP_PORT"); [[ "$TLS_MODE" == proxy ]] || ports+=("$GRPC_PORT")
 if command -v ufw >/dev/null && LC_ALL=C ufw status | grep -q '^Status: active'; then
  for port in "${ports[@]}"; do ufw allow "$port/tcp"; done
 elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
  for port in "${ports[@]}"; do firewall-cmd --permanent --add-port="$port/tcp"; firewall-cmd --add-port="$port/tcp"; done
 fi
fi
log "安装完成，面板及数据库已设置开机自启。"
authority=$HOST; [[ "$HOST" != *:* ]] || authority="[$HOST]"
printf '面板地址：http://%s:%s\n管理员账号：%s\n服务菜单：nekopassctl\n重置密码：nekopassctl %s reset-password\n' "$authority" "$HTTP_PORT" "$ADMIN" "$([[ "$SERVICE" == nekopass ]] && echo panel || echo "$SERVICE")"
cat "$WORK/admin-result"
if [[ "$TLS_MODE" == proxy ]]; then log "已选择现有代理模式，请确保外部 TLS 入口代理到 127.0.0.1:$GRPC_PORT。"; fi
log "使用云服务器时，还需在云平台安全组放行网页 $HTTP_PORT 和节点连接 $AGENT_PORT。"

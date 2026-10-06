#!/usr/bin/env bash
# Nekopass native systemd installer. No containers and no remote shell evaluation.
set -Eeuo pipefail
umask 077

# Release packaging embeds the manager here; repository runs use the sibling file.
write_manager_payload() { return 1; }
# PACKAGED_MANAGER
write_updater_payload() { return 1; }
# PACKAGED_UPDATER

SERVER=''; TOKEN=''; TOKEN_FILE=''; PANEL_URL=''; INSTALL_TOKEN=''
DOWNLOAD_BASE='https://github.com/hajidishu/nekopass/releases/download'
VERSION='v0.14.4'; ARCH='auto'; BINARY_URL=''
SERVICE='nekopass-agent'
UPGRADE=0; NO_START=0; DRY_RUN=0; WORK=''; CHANGED=0; WAS_ACTIVE=0; WAS_ENABLED=0
usage() {
 cat <<'HELP'
Nekopass Agent installer (Linux + systemd, run as root)

Direct mode:
  bash install-agent.sh -s https://panel.example.com:9443 -t NODE_TOKEN \
    -d https://github.com/hajidishu/nekopass/releases/download -v v0.14.4

Panel-issued install command:
  bash install-agent.sh -p https://panel.example.com -i INSTALL_TOKEN

  -s, --server URL             https://host:port for public TLS; http://host:port for test h2c
  -t, --token TOKEN            Node token, never a global management API key
      --token-file PATH       Read node token from a file
  -p, --panel-url URL          HTTP(S) control-panel API root
  -i, --install-token TOKEN    One-time node-specific installation credential
  -d, --download-base URL      HTTPS release directory
  -v, --version VERSION        Release directory name; default v0.14.4
  -a, --arch ARCH              auto, amd64 or arm64
      --binary-url URL        Override architecture binary download URL
      --service-name NAME     Default nekopass-agent; isolated suffix allowed
      --upgrade               Require an existing installation, preserve identity
      --no-start              Install files only; do not enable/start the service
      --dry-run               Print non-secret plan; no downloads or changes
  -h, --help                  Show this help

Existing installations preserve state and credentials. Changing a node token
on an installed service is refused. No bandwidth/port/resource flags are needed:
those settings are delivered by the control panel.
The release installer also installs the service menu: nekopassctl
HELP
}
die() { printf '[nekopass] ERROR: %s\n' "$*" >&2; exit 1; }
log() { printf '[nekopass] %s\n' "$*"; }
need_value() { [[ $# -ge 2 && -n "$2" ]] || die "Missing value for $1"; }
while (($#)); do
 case "$1" in
  -h|--help) usage; exit 0;;
  -s|--server) need_value "$@"; SERVER=$2; shift 2;;
  -t|--token) need_value "$@"; TOKEN=$2; shift 2;;
  --token-file) need_value "$@"; TOKEN_FILE=$2; shift 2;;
  -p|--panel-url) need_value "$@"; PANEL_URL=${2%/}; shift 2;;
  -i|--install-token) need_value "$@"; INSTALL_TOKEN=$2; shift 2;;
  -d|--download-base) need_value "$@"; DOWNLOAD_BASE=${2%/}; shift 2;;
  -v|--version) need_value "$@"; VERSION=$2; shift 2;;
  -a|--arch) need_value "$@"; ARCH=$2; shift 2;;
  --binary-url) need_value "$@"; BINARY_URL=$2; shift 2;;
  --service-name) need_value "$@"; SERVICE=$2; shift 2;;
  --upgrade) UPGRADE=1; shift;;
  --no-start) NO_START=1; shift;;
  --dry-run) DRY_RUN=1; shift;;
  *) die "Unknown option: $1 (use --help)";;
 esac
done
[[ "$SERVICE" =~ ^nekopass-agent(-[a-z0-9]{1,16})?$ ]] || die 'Invalid service name'
[[ "$VERSION" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ && "$VERSION" != *..* ]] || die 'Invalid version'
case "$(uname -m)" in x86_64|amd64) MACHINE=amd64;; aarch64|arm64) MACHINE=arm64;; *) die 'Only Linux amd64/arm64 are supported';; esac
[[ "$(uname -s)" == Linux ]] || die 'Linux is required'
[[ "$ARCH" != auto ]] || ARCH=$MACHINE
[[ "$ARCH" == "$MACHINE" ]] || die 'Selected architecture does not match this machine'
if ((DRY_RUN)); then
 log "Dry run: architecture=$ARCH service=$SERVICE version=$VERSION"
 if [[ -n "$INSTALL_TOKEN" ]]; then log 'Configuration would be redeemed from the panel; no credential consumed.'; else log 'Direct installation; secrets are not displayed.'; fi
 exit 0
fi
[[ $(id -u) -eq 0 ]] || die 'Run this script as root'
command -v systemctl >/dev/null && [[ -d /run/systemd/system ]] || die 'A running systemd host is required'
if ! command -v curl >/dev/null || ! command -v python3 >/dev/null; then
 log 'Installing curl, CA certificates, Python 3 and core utilities'
 if command -v apt-get >/dev/null; then export DEBIAN_FRONTEND=noninteractive; apt-get update; apt-get install -y curl ca-certificates python3 coreutils
 elif command -v dnf >/dev/null; then dnf install -y curl ca-certificates python3 coreutils
 elif command -v yum >/dev/null; then yum install -y curl ca-certificates python3 coreutils
 else die 'Install curl, ca-certificates, python3 and coreutils first'; fi
fi
if [[ "$SERVICE" == nekopass-agent ]]; then
 BIN=/opt/nekopass/bin/nekopass-agent; CONFIG_DIR=/etc/nekopass
else
 BIN="/opt/$SERVICE/bin/nekopass-agent"; CONFIG_DIR="/etc/$SERVICE"
fi
ENV_FILE="$CONFIG_DIR/agent.env"; STATE_DIR="/var/lib/$SERVICE"; UNIT="/etc/systemd/system/$SERVICE.service"
for target in "$(dirname "$BIN")" "$CONFIG_DIR" "$STATE_DIR" /etc/systemd/system; do
 [[ "$(realpath -m "$target")" == "$target" ]] || die "Refusing symlinked installation directory: $target"
done
for target in "$BIN" "$ENV_FILE" "$UNIT"; do [[ ! -L "$target" ]] || die "Refusing symlink: $target"; done
if ((UPGRADE)); then [[ -f "$ENV_FILE" ]] || die 'Existing configuration missing; use a new node for a new host'; fi
if [[ ! -f "$ENV_FILE" && -d "$STATE_DIR" ]] && find "$STATE_DIR" -maxdepth 1 -name '*.db' -print -quit | grep -q .; then die 'State exists without configuration. Restore the original agent.env; state will not be reset.'; fi
WORK=$(mktemp -d /tmp/nekopass-install.XXXXXXXX)
[[ "$WORK" == /tmp/nekopass-install.* ]] || die 'Invalid temporary directory'
MANAGER_SOURCE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/nekopassctl.sh"
UPDATER_SOURCE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/nekopass-update.py"
if ! write_updater_payload > "$WORK/nekopass-update"; then
 [[ -f "$UPDATER_SOURCE" ]] || die 'Use the GitHub release installer (updater payload missing)'
 cp "$UPDATER_SOURCE" "$WORK/nekopass-update"
fi
if ! write_manager_payload > "$WORK/nekopassctl"; then
 if [[ -f "$MANAGER_SOURCE" ]]; then
  tr -d '\r' < "$MANAGER_SOURCE" > "$WORK/nekopassctl"
 else
  rm -f "$WORK/nekopassctl"
  log 'CLI companion missing. Use the packaged installer to install nekopassctl automatically.'
 fi
fi
cleanup() {
 local status=$?
 trap - EXIT
 if ((status != 0 && CHANGED)); then
  log 'Installation failed; stopping the service'
  systemctl stop "$SERVICE" >/dev/null 2>&1 || true
  if [[ ! -f "$WORK/backup-env" ]]; then
   # The Agent may already have registered its durable identity. Keep its
   # credentials alongside that state so a fresh command can safely retry.
   systemctl disable "$SERVICE" >/dev/null 2>&1 || true
   log "New installation files retained at $CONFIG_DIR; retry without deleting state."
   rm -rf -- "$WORK"
   exit "$status"
  fi
  log 'Restoring previous installation files'
  for key in binary env unit; do
   case "$key" in binary) dest=$BIN;; env) dest=$ENV_FILE;; unit) dest=$UNIT;; esac
   if [[ -f "$WORK/backup-$key" ]]; then cp -p "$WORK/backup-$key" "$dest"; else rm -f -- "$dest"; fi
  done
  systemctl daemon-reload >/dev/null 2>&1 || true
  if ((WAS_ENABLED)); then systemctl enable "$SERVICE" >/dev/null 2>&1 || true; else systemctl disable "$SERVICE" >/dev/null 2>&1 || true; fi
  if ((WAS_ACTIVE)); then systemctl start "$SERVICE" >/dev/null 2>&1 || true; fi
 fi
 rm -rf -- "$WORK"
 exit "$status"
}
trap cleanup EXIT
read_env() {
 python3 - "$ENV_FILE" "$1" <<'PY'
import pathlib,sys
p=pathlib.Path(sys.argv[1])
if p.exists():
 for line in p.read_text().splitlines():
  if line.startswith(sys.argv[2]+'='):
   value=line.split('=',1)[1].strip()
   if len(value)>1 and value[0]==value[-1] and value[0] in "\"'":value=value[1:-1]
   print(value,end='');break
PY
}
OLD_TOKEN=$(read_env NEKOPASS_NODE_TOKEN); OLD_SERVER=$(read_env NEKOPASS_SERVER)
[[ ! -f "$ENV_FILE" || -n "$OLD_TOKEN" ]] || die 'Existing node token missing; refusing to overwrite identity'
if [[ -n "$TOKEN_FILE" ]]; then [[ -f "$TOKEN_FILE" ]] || die 'Token file missing'; TOKEN=$(cat "$TOKEN_FILE"); fi
[[ -n "$TOKEN" ]] || TOKEN=$OLD_TOKEN
[[ -n "$SERVER" ]] || SERVER=$OLD_SERVER
check_url() { python3 - "$1" <<'PY'
import sys,urllib.parse
u=urllib.parse.urlsplit(sys.argv[1])
if u.scheme!='https' or not u.hostname or u.username or u.password or u.fragment or any(c in sys.argv[1] for c in '\r\n\0'):sys.exit('HTTPS URL required')
PY
}
fetch() { check_url "$1"; curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 15 --max-time 300 --retry 3 "$1" -o "$2"; }
if [[ -n "$PANEL_URL" ]]; then check_url "${PANEL_URL/#http:\/\//https:\/\/}"; fi
if [[ -n "$INSTALL_TOKEN" ]]; then
 [[ -n "$PANEL_URL" ]] || die '--panel-url is required with --install-token'
 check_url "${PANEL_URL/#http:\/\//https:\/\/}"; [[ "$INSTALL_TOKEN" =~ ^[a-fA-F0-9]{64}$ ]] || die 'Invalid install token'
 if [[ -n "$TOKEN" ]]; then [[ "$TOKEN" =~ ^[A-Za-z0-9_-]{8,128}$ ]] || die 'Invalid existing node token'; fi
 printf 'header = "Authorization: Bearer %s"\n' "$INSTALL_TOKEN" > "$WORK/auth.conf"
 printf '%s' "$TOKEN" > "$WORK/token"
 python3 - "$WORK/token" "$WORK/request.json" <<'PY'
import json,pathlib,sys
pathlib.Path(sys.argv[2]).write_text(json.dumps({'current_token':pathlib.Path(sys.argv[1]).read_text()}))
PY
 log 'Redeeming node-specific installation credential'
 code=$(curl --silent --show-error --proto '=http,https' --tlsv1.2 --connect-timeout 15 --max-time 30 --config "$WORK/auth.conf" -H 'Content-Type: application/json' --data-binary "@$WORK/request.json" "$PANEL_URL/api/v1/node-install/redeem" -o "$WORK/bootstrap.json" -w '%{http_code}')
 if [[ "$code" != 200 ]]; then python3 - "$WORK/bootstrap.json" <<'PY'
import json,sys
try:print('[nekopass] '+str(json.load(open(sys.argv[1])).get('error','Installation credential rejected')),file=sys.stderr)
except Exception:print('[nekopass] Panel rejected installation',file=sys.stderr)
PY
  exit 1
 fi
 python3 - "$WORK/bootstrap.json" "$WORK" "$ARCH" <<'PY'
import json,pathlib,sys
v=json.load(open(sys.argv[1]));root=pathlib.Path(sys.argv[2]);arch=sys.argv[3]
for key in ['server','token','version','download_base']:
 value=v.get(key,'')
 if not isinstance(value,str) or any(c in value for c in '\r\n\0'):raise ValueError('Invalid bootstrap field')
 (root/key).write_text(value)

PY
 SERVER=$(cat "$WORK/server"); TOKEN=$(cat "$WORK/token"); VERSION=$(cat "$WORK/version"); DOWNLOAD_BASE=$(cat "$WORK/download_base")

fi
[[ "$TOKEN" =~ ^[A-Za-z0-9_-]{8,128}$ ]] || die 'A valid node token is required'
[[ -z "$OLD_TOKEN" || "$TOKEN" == "$OLD_TOKEN" ]] || die 'Refusing to replace an existing node identity; use its original token or a new host'
python3 - "$SERVER" <<'PY'
import re,sys,urllib.parse
raw=sys.argv[1]
if any(c in raw for c in '\r\n\0'):sys.exit('Invalid server endpoint')
v=urllib.parse.urlsplit(raw if '://' in raw else '//'+raw)
try:port=v.port
except ValueError:sys.exit('Invalid server port')
if v.scheme not in ('','http','https') or not v.hostname or not port or not 1<=port<=65535 or v.path not in ('','/') or v.query or v.fragment or v.username or v.password:sys.exit('Use https://host:port or http://host:port')
PY
[[ "$VERSION" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ && "$VERSION" != *..* ]] || die 'Invalid release version'
if [[ -z "$BINARY_URL" ]]; then
 [[ -n "$DOWNLOAD_BASE" ]] || die 'Configure --download-base or the panel download settings'
 check_url "$DOWNLOAD_BASE"
 [[ "$DOWNLOAD_BASE" != *YOUR-OSS.example.com* ]] || die 'Configure a real download URL via --download-base or panel settings'
fi
FILE="nekopass-agent-linux-$ARCH"
if [[ -z "$BINARY_URL" ]]; then
 if [[ "$VERSION" == latest && "$DOWNLOAD_BASE" == https://github.com/hajidishu/nekopass/releases/download ]]; then
  BINARY_URL="https://github.com/hajidishu/nekopass/releases/latest/download/$FILE"
 else BINARY_URL="$DOWNLOAD_BASE/$VERSION/$FILE"; fi
fi

log "Downloading Agent $VERSION for linux/$ARCH"
fetch "$BINARY_URL" "$WORK/agent"; chmod 700 "$WORK/agent"
"$WORK/agent" -version > "$WORK/version-check" || die 'Downloaded binary cannot run on this machine'
grep -q '^nekopass-agent ' "$WORK/version-check" || die 'Unexpected agent binary'
REPORTED_VERSION=$(awk '{print $2}' "$WORK/version-check")
[[ "$REPORTED_VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die 'Unexpected release version'
[[ "$VERSION" == latest || "$VERSION" == "$REPORTED_VERSION" ]] || die 'Downloaded binary version mismatch'
VERSION=$REPORTED_VERSION
id -u "$SERVICE" >/dev/null 2>&1 || useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin "$SERVICE"
install -d -m 755 "$(dirname "$BIN")" "$CONFIG_DIR"
for key in binary env unit; do
 case "$key" in binary) src=$BIN;; env) src=$ENV_FILE;; unit) src=$UNIT;; esac
 [[ ! -f "$src" ]] || cp -p "$src" "$WORK/backup-$key"
done
if systemctl is-active --quiet "$SERVICE"; then WAS_ACTIVE=1; fi
if systemctl is-enabled --quiet "$SERVICE" 2>/dev/null; then WAS_ENABLED=1; fi
CHANGED=1
systemctl stop "$SERVICE" 2>/dev/null || true
install -m 755 "$WORK/agent" "$BIN"
printf 'NEKOPASS_SERVER=%s\nNEKOPASS_NODE_TOKEN=%s\n' "$SERVER" "$TOKEN" > "$WORK/agent.env"
if [[ -n "$PANEL_URL" ]]; then printf 'NEKOPASS_PANEL_URL=%s\n' "$PANEL_URL" >> "$WORK/agent.env"; fi
install -m 600 "$WORK/agent.env" "$ENV_FILE"
cat > "$WORK/agent.service" <<UNIT
[Unit]
Description=Nekopass TCP forwarding agent
After=network-online.target
Wants=network-online.target
ConditionPathExists=$ENV_FILE

[Service]
Type=simple
User=$SERVICE
Group=$SERVICE
EnvironmentFile=$ENV_FILE
ExecStart=$BIN -state $STATE_DIR/state.db
Restart=on-failure
RestartSec=3
TimeoutStopSec=30
StateDirectory=$SERVICE
StateDirectoryMode=0700
UMask=0077
NoNewPrivileges=true
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT
install -m 644 "$WORK/agent.service" "$UNIT"
install -m 755 "$WORK/nekopass-update" "$(dirname "$BIN")/nekopass-update"
cat > "$WORK/update.service" <<UNIT
[Unit]
Description=Nekopass Agent release updater
[Service]
Type=oneshot
ExecStart=$(dirname "$BIN")/nekopass-update --service $SERVICE --request
TimeoutStartSec=600
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=$(dirname "$(dirname "$BIN")") $STATE_DIR /run/lock
UNIT
cat > "$WORK/update.path" <<UNIT
[Unit]
Description=Watch Nekopass Agent update requests
[Path]
PathExists=$STATE_DIR/update-request.json
Unit=$SERVICE-update.service
[Install]
WantedBy=multi-user.target
UNIT
install -m 644 "$WORK/update.service" "/etc/systemd/system/$SERVICE-update.service"
install -m 644 "$WORK/update.path" "/etc/systemd/system/$SERVICE-update.path"
systemctl daemon-reload
systemctl enable --now "$SERVICE-update.path" >/dev/null
if ((!NO_START)); then
 systemctl enable "$SERVICE" >/dev/null
 systemctl restart "$SERVICE"
 sleep 2
 systemctl is-active --quiet "$SERVICE" || die 'Agent failed to start; previous installation will be restored'
fi
if [[ -f "$WORK/nekopassctl" ]]; then
 bash -n "$WORK/nekopassctl"
 install -d -m 755 /usr/local/bin
 install -m 755 "$WORK/nekopassctl" /usr/local/bin/nekopassctl
 log 'Service menu installed. Run: nekopassctl'
fi
CHANGED=0
log "Installed $VERSION. Configuration: $ENV_FILE"
log "State preserved at $STATE_DIR. Check: journalctl -u $SERVICE -n 50 --no-pager"
if ((NO_START)); then log "Files installed only. Start with: systemctl enable --now $SERVICE";else log 'Service running. Confirm the node is online and synchronized in the panel.';fi

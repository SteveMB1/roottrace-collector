#!/bin/sh
set -eu

INSTALL_DIR="${ROOTTRACE_INSTALL_DIR:-/opt/roottrace-collector}"
CONFIG_DIR="${ROOTTRACE_CONFIG_DIR:-/etc/roottrace}"
CONFIG_FILE="${CONFIG_DIR}/collector.env"
STATE_DIR="${ROOTTRACE_STATE_DIR:-/var/lib/roottrace-collector}"
SERVICE_FILE="/etc/systemd/system/roottrace-collector.service"
COLLECTOR_USER="${ROOTTRACE_COLLECTOR_USER:-roottrace-collector}"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this uninstaller as root, for example with sudo." >&2
  exit 1
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now roottrace-collector.service >/dev/null 2>&1 || true
fi

remove_nginx_log_acl() {
  if ! command -v setfacl >/dev/null 2>&1; then
    return 0
  fi
  nginx_targets="/var/log/nginx"
  if [ -f "$CONFIG_FILE" ]; then
    configured_targets="$(sed -n 's/^ROOTTRACE_NGINX_\(ACCESS\|ERROR\)_LOG_PATHS\?=//p' "$CONFIG_FILE" | tr ',' ' ')"
    nginx_targets="${nginx_targets} ${configured_targets}"
  fi

  for path in $nginx_targets; do
    [ -n "$path" ] || continue
    case "$path" in
      *'*'*|*'?'*) continue ;;
    esac
    if [ -L "$path" ]; then
      continue
    fi
    if [ -d "$path" ]; then
      setfacl -x "u:${COLLECTOR_USER}" "$path" 2>/dev/null || true
      setfacl -x "d:u:${COLLECTOR_USER}" "$path" 2>/dev/null || true
      for file in "$path"/access.log "$path"/access.log.1 "$path"/error.log "$path"/error.log.1; do
        if [ -f "$file" ] && [ ! -L "$file" ]; then
          setfacl -x "u:${COLLECTOR_USER}" "$file" 2>/dev/null || true
        fi
      done
    elif [ -f "$path" ]; then
      setfacl -x "u:${COLLECTOR_USER}" "$path" 2>/dev/null || true
    fi
  done
}

remove_nginx_log_acl

rm -f "$SERVICE_FILE"
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
fi

if [ "${ROOTTRACE_PURGE_COLLECTOR_STATE:-false}" = "true" ]; then
  rm -rf "$INSTALL_DIR" "$CONFIG_FILE" "$STATE_DIR"
else
  rm -rf "$INSTALL_DIR"
  echo "Preserved ${CONFIG_FILE} and ${STATE_DIR}. Set ROOTTRACE_PURGE_COLLECTOR_STATE=true to remove them."
fi

echo "RootTrace collector service removed."

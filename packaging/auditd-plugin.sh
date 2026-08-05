#!/bin/sh
# RootTrace auditd realtime plugin wrapper (native package)
#   -> /usr/libexec/roottrace-collector/auditd-plugin.sh
#
# auditd execs this for every plugin dispatch; roottrace-collector-setup points
# /etc/audit/plugins.d/roottrace.conf at it.
set -eu
# Keep this auditd child side-effect free under SELinux auditd_t.
export PYTHONDONTWRITEBYTECODE=1
export PYTHONUNBUFFERED=1
export ROOTTRACE_LINUX_AUDIT_PLUGIN_MINIMAL_HOST=true
exec /usr/bin/roottrace-collector --env-file /etc/roottrace/collector.env --auditd-plugin

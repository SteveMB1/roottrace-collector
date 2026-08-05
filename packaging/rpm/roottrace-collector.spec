# RootTrace collector RPM. Built by deploy/pipeline/buildspec-packages.yml,
# which passes the version from collector/roottrace_collector.py:
#   rpmbuild -bb --define "collector_version X.Y.Z" roottrace-collector.spec
#
# noarch and never compiled: the collector ships as the same plain-source
# Python file every install method runs, so what executes on the host is
# byte-identical to what an auditor reads. Scriptlets are spelled out rather
# than using %systemd_post/%sysusers macros because the pipeline builds this
# on an Ubuntu CodeBuild image where the RHEL macro packages don't exist.
#
# File placement follows the DISA STIG for RHEL: executables under /usr/bin,
# /usr/sbin, and /usr/libexec, root-owned and never group/world-writable
# (RHEL-10-232010 family); configuration root-owned 0600 in /etc; variable
# state under /var/lib with nothing executable in it. Nothing lands in /opt,
# so noexec mounts on /opt, /var, and /tmp never break the collector.

Name:           roottrace-collector
Version:        %{?collector_version}%{!?collector_version:0.0.0}
Release:        %{?collector_release}%{!?collector_release:1}
Summary:        RootTrace read-only diagnostics collector
License:        Apache-2.0
URL:            https://roottrace.io/docs/collector/
Source0:        roottrace-collector-%{version}.tar.gz
BuildArch:      noarch

Requires:       python3 >= 3.9
Requires:       systemd
# setfacl for the read-only log ACLs roottrace-collector-setup grants; the
# optional database monitors use distro driver packages when present.
Recommends:     acl
Recommends:     python3-psycopg2
Recommends:     python3-pymongo

%description
Outbound-only, read-only diagnostics collector for RootTrace. Sends
heartbeats and diagnostics to the RootTrace API over short-lived HTTPS
requests; opens no inbound ports, executes no remediation, and mutates no
customer configuration. Configure /etc/roottrace/collector.env, run
roottrace-collector-setup apply, then enable roottrace-collector.service.

%prep
%setup -q

%build
# Nothing to build: the collector is deliberately shipped as plain source.

%install
install -D -m 0755 roottrace_collector.py %{buildroot}/usr/libexec/roottrace-collector/roottrace_collector.py
install -D -m 0755 packaging/auditd-plugin.sh %{buildroot}/usr/libexec/roottrace-collector/auditd-plugin.sh
install -d -m 0755 %{buildroot}/usr/libexec/roottrace-collector/additional_monitors
install -m 0644 additional_monitors/*.py %{buildroot}/usr/libexec/roottrace-collector/additional_monitors/
install -D -m 0755 packaging/roottrace-collector %{buildroot}/usr/bin/roottrace-collector
install -D -m 0755 packaging/roottrace-collector-setup %{buildroot}/usr/sbin/roottrace-collector-setup
install -D -m 0644 packaging/roottrace-collector.service %{buildroot}/usr/lib/systemd/system/roottrace-collector.service
install -D -m 0600 packaging/collector.env %{buildroot}/etc/roottrace/collector.env
install -d -m 0750 %{buildroot}/var/lib/roottrace-collector

%pre
getent group roottrace-collector >/dev/null 2>&1 || groupadd -r roottrace-collector
getent passwd roottrace-collector >/dev/null 2>&1 || \
  useradd -r -g roottrace-collector -d /var/lib/roottrace-collector \
    -s /usr/sbin/nologin -c "RootTrace collector" roottrace-collector
exit 0

%post
# A shell-installer deployment leaves its unit in /etc, which takes
# precedence over this package's unit and points at /opt/roottrace-collector.
# Retire only the unit with the shell installer's distinctive updater line;
# leave unrelated local overrides alone.
legacy_unit=/etc/systemd/system/roottrace-collector.service
legacy_enabled=false
legacy_active=false
if [ -f "$legacy_unit" ] &&
  grep -qF 'ExecStartPre=+/opt/roottrace-collector/update_collector.sh' "$legacy_unit"; then
  systemctl is-enabled roottrace-collector.service >/dev/null 2>&1 && legacy_enabled=true
  systemctl is-active roottrace-collector.service >/dev/null 2>&1 && legacy_active=true
  rm -f "$legacy_unit"
fi

systemctl daemon-reload >/dev/null 2>&1 || :
if [ "$legacy_enabled" = true ]; then
  systemctl reenable roottrace-collector.service >/dev/null 2>&1 || :
fi
if [ "$legacy_active" = true ]; then
  systemctl restart roottrace-collector.service >/dev/null 2>&1 || :
fi
exit 0

%preun
# $1 == 0: full erase. Stop the service and undo the host integration
# (ACLs, audit rules, auditd plugin conf) while the helper still exists,
# so `dnf remove` leaves no RootTrace state behind.
if [ $1 -eq 0 ]; then
  systemctl --no-reload disable --now roottrace-collector.service >/dev/null 2>&1 || :
  /usr/sbin/roottrace-collector-setup remove >/dev/null 2>&1 || :
fi
exit 0

%postun
systemctl daemon-reload >/dev/null 2>&1 || :
if [ $1 -ge 1 ]; then
  # Upgrade: pick up the new collector on the next cycle.
  systemctl try-restart roottrace-collector.service >/dev/null 2>&1 || :
fi
if [ $1 -eq 0 ]; then
  # Erase: clear runtime state. A locally modified collector.env is kept as
  # /etc/roottrace/collector.env.rpmsave (standard %config(noreplace)
  # behavior) because it can hold credentials the operator may still need.
  rm -rf /var/lib/roottrace-collector
fi
exit 0

%files
%license LICENSE
%doc README.md
/usr/bin/roottrace-collector
/usr/sbin/roottrace-collector-setup
%dir /usr/libexec/roottrace-collector
/usr/libexec/roottrace-collector/roottrace_collector.py
/usr/libexec/roottrace-collector/auditd-plugin.sh
%dir /usr/libexec/roottrace-collector/additional_monitors
/usr/libexec/roottrace-collector/additional_monitors/*.py
/usr/lib/systemd/system/roottrace-collector.service
%dir %attr(0755,root,root) /etc/roottrace
%config(noreplace) %attr(0600,root,root) /etc/roottrace/collector.env
%dir %attr(0750,roottrace-collector,roottrace-collector) /var/lib/roottrace-collector

%changelog
# Release history lives in the collector guide and the repository CHANGELOG;
# package NVRs track collector/roottrace_collector.py VERSION.

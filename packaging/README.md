# Collector native packaging

Sources for the `roottrace-collector` RPM and DEB that
`deploy/pipeline/buildspec-packages.yml` builds, signs, and publishes to the
dnf/apt repositories at https://packages.roottrace.io. See the
[release pipeline guide](../../deploy/pipeline/README.md) for the maintainer
workflow and the [collector guide](../../docs/collector-guide.md) for the
customer-facing install flow.

The static runtime and service files are real, package-owned files, so the
package manager tracks every path and `dnf remove` / `apt remove` takes
the collector and its host integration with it (bar two deliberately-kept
host-wide settings noted in the collector guide's removal section):

| File | Installs to | Role |
| --- | --- | --- |
| `roottrace-collector.service` | `/usr/lib/systemd/system/` | hardened unit (no self-update; upgrades come from the package manager) |
| `roottrace-collector` | `/usr/bin/` | runtime wrapper: find python3, exec the collector |
| `roottrace-collector-setup` | `/usr/sbin/` | dynamic host integration: ACLs, SELinux boolean, optional STIG audit rules, auditd plugin; `apply` and `remove` |
| `auditd-plugin.sh` | `/usr/libexec/roottrace-collector/` | auditd realtime plugin entry point |
| `collector.env` | `/etc/roottrace/` (0600, config-noreplace) | configuration template |
| `rpm/roottrace-collector.spec` | — | RPM build recipe (noarch, plain source, no compilation) |
| `deb/` | — | DEB control file template, conffiles, maintainer scripts |

The collector itself (`collector/roottrace_collector.py`) and the bundled
monitors (`collector/additional_monitors/`) are packaged from their normal
locations; nothing is duplicated here and nothing is compiled.

Host-specific state the package cannot own (audit rule files generated per
host kernel, the auditd plugin pointer conf, POSIX ACLs) is created by
`roottrace-collector-setup apply` and torn down by
`roottrace-collector-setup remove`, which both packages' pre-removal scripts
run automatically — that is what keeps package removal complete.

On installation, the RPM and DEB recognize a retired shell install's
`/etc/systemd/system/roottrace-collector.service` by its
`ExecStartPre=+/opt/roottrace-collector/update_collector.sh` line. They remove
that higher-precedence unit, reload systemd, preserve its enabled state, and
restart it if it was active. Other local unit overrides are not touched.

File placement follows the DISA STIG for RHEL: executables root-owned under
`/usr/bin`, `/usr/sbin`, `/usr/libexec` (0755, never group/world-writable),
config 0600 root:root under `/etc/roottrace`, state 0750 under
`/var/lib/roottrace-collector`, nothing in `/opt`, nothing executable under
`/var` or `/tmp`.

Version comes from `VERSION` in `collector/roottrace_collector.py`; bump it
to publish a new package. The buildspec skips any version the repos already
carry, so a given NVR is only ever published once.

# RootTrace Collector — source tree

The collector is an outbound-only, read-only diagnostics agent. Each cycle it
POSTs a heartbeat and a diagnostics payload to the RootTrace API and closes the
connection. It opens no inbound ports, runs no remediation, never restarts
services, never mutates Kubernetes resources, never writes customer
configuration, and never reads cloud credentials.

**This file describes the source tree.** If you are installing or operating the
collector, you want the customer documentation instead:

| | |
| --- | --- |
| Install, upgrade, uninstall, security model | [`docs/collector-guide.md`](../docs/collector-guide.md) |
| Every check and its tunables | [`docs/collector-checks.md`](../docs/collector-checks.md) |
| Linux audit ingestion and compliance reports | [`docs/linux-audit-guide.md`](../docs/linux-audit-guide.md) |
| Air-gapped mirroring | [`docs/air-gap-install.md`](../docs/air-gap-install.md) |

## What is here

```text
roottrace_collector.py    the whole collector, plain Python, no compilation
additional_monitors/      shipped read-only custom-metric modules (KEDA, ...)
packaging/                RPM spec, DEB control, hardened unit, setup helper
kubernetes/               the DaemonSet manifest (ships a zero image digest)
ansible/                  playbook for checkout-based installs
install/                  retired shell-installer artifacts, kept for uninstall
Dockerfile                the agent image
```

`VERSION` in `roottrace_collector.py` drives the package version. Bump it to
publish a new package; the build skips any version the repositories already
carry, so a given NVR is published exactly once. See
[`packaging/README.md`](packaging/README.md).

Nothing is compiled. The packages install the collector as plain Python source,
so what executes on a host is byte-identical to what is in this directory —
which is the point, for anyone auditing it.

## Local development

One-shot run against a local API:

```sh
ROOTTRACE_COLLECTOR_TOKEN=rtc_... \
ROOTTRACE_API_URL=http://localhost:8090/api \
python3 collector/roottrace_collector.py --once
```

Local image:

```sh
docker build -t roottrace-agent:local collector
```

Optional third-party libraries (pymongo, psycopg, mysql-connector-python,
cassandra-driver, python3-dbus, python3-systemd, playwright, cryptography) are
import-guarded. A missing library degrades the matching check to a dependency
warning rather than failing the collector or shelling out to a workaround.

## The two published channels

Both are built and signed by the release pipeline, not from a developer machine:

- GPG-signed dnf and apt repositories at `https://packages.roottrace.io`, built
  from `packaging/` by `deploy/pipeline/buildspec-packages.yml`.
- The digest-pinned agent image in the
  [ECR Public Gallery](https://gallery.ecr.aws/h4o5i5r8/roottrace/agent), used
  by both the Docker and Kubernetes install paths.

The Ansible playbook copies collector source from a trusted checkout. It is
deployment automation, not a third download channel, and it has no updater.

A collector artifact from anywhere else is not a RootTrace artifact.

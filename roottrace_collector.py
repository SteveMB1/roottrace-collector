#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import binascii
import csv
import hashlib
import http.client
import importlib.util
import inspect
import json
import math
import os
import platform
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections import deque
from urllib.parse import quote, unquote, urlencode, urlparse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

try:
    import pwd
except ImportError:  # pragma: no cover - non-Unix local static checks.
    pwd = None

VERSION = "0.3.5"
SENSITIVE_KEYS = ("password", "passwd", "secret", "token", "api_key", "apikey", "authorization", "cookie", "credential")
# Inline `key=value` / `key: value` secrets in free text (log lines, evidence
# strings). The key stays visible so the line is still diagnostic; only the
# value is replaced. Mirrors SENSITIVE_KEY_PATTERN in src/roottrace_redaction.py.
SENSITIVE_KEY_VALUE_RE = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|apikey|authorization|cookie|credential)"
    r"(\s*[:=]\s*)"
    r"(\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
)
SECRET_VALUE_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)(aws_secret_access_key\s*[:=]\s*)[A-Za-z0-9/+=]{30,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL),
)
PSEUDO_FILESYSTEMS = {
    "autofs",
    "binfmt_misc",
    "bpf",
    "cgroup",
    "cgroup2",
    "configfs",
    "debugfs",
    "devpts",
    "devtmpfs",
    "efivarfs",
    "fusectl",
    "hugetlbfs",
    "mqueue",
    "overlay",
    "proc",
    "pstore",
    "rpc_pipefs",
    "securityfs",
    "selinuxfs",
    "sysfs",
    "tmpfs",
    "tracefs",
    "selinux",
}
IGNORED_DISK_PATHS = {
    "/sys/fs/selinux",
}
IGNORED_DISK_PATH_PREFIXES = (
    "/run",
    "/snap",
    "/var/lib/kubelet/pods",
)
CHECK_TIMEOUT_SECONDS = 4.0
KUBERNETES_TOKEN_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
KUBERNETES_CA_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
KUBERNETES_KUBECONFIG_ENV_NAMES = (
    "ROOTTRACE_KUBERNETES_KUBECONFIG",
    "ROOTTRACE_KUBECONFIG",
    "ROOTTRACE_KEDA_KUBECONFIG",
    "KUBECONFIG",
)
KUBERNETES_DEFAULT_KUBECONFIG_PATHS = (
    "/etc/roottrace/kubeconfig",
    "/etc/kubernetes/admin.conf",
    "/etc/kubernetes/kubelet.conf",
    "/etc/rancher/k3s/k3s.yaml",
    "/etc/rancher/rke2/rke2.yaml",
    "/var/snap/microk8s/current/credentials/client.config",
    "/root/.kube/config",
    "~/.kube/config",
)
LINUX_AUDIT_KV_RE = re.compile(r'(\w+)=("[^"]*"|\S+)')
LINUX_AUDIT_MSG_RE = re.compile(r"msg=audit\(([^)]+)\)")
LINUX_AUDIT_UNSET_UID_VALUES = {"", "-1", "4294967295", "unset", "(unset)", "none", "null"}
LINUX_AUDIT_UID_CACHE: dict[str, dict[str, Any]] = {}
LAST_CHECK_DURATIONS_MS: dict[str, float] = {}
LAST_LINUX_AUDIT_STATS: dict[str, Any] = {}
LAST_LOG_SHIP_STATS: dict[str, Any] = {}
LOG_LEVEL_MARKER_RE = re.compile(r"\b(FATAL|CRITICAL|ERROR|ERR|WARNING|WARN|INFO|DEBUG|TRACE)\b", re.IGNORECASE)
VALID_RESULT_STATUSES = {"pass", "warn", "fail", "unknown"}
VALID_RESULT_SEVERITIES = {"info", "low", "medium", "high", "critical"}
WARNING_THRESHOLD_KEYS = ("warn", "warning", "warn_threshold", "warning_threshold")
ERROR_THRESHOLD_KEYS = ("fail", "error", "fail_threshold", "error_threshold")


# --- Tunables --------------------------------------------------------------
# Every ROOTTRACE_* knob the collector reads goes through env()/env_bool()/
# env_int()/env_float(), so those four are the only place that knows a
# tunable's name, its type, and the default the code actually asked for. Each
# read records itself in TUNABLE_CATALOG, which is what lets the collector
# report its own catalog on heartbeat instead of the server keeping a
# hand-written copy that drifts from the code the moment a default changes.
# The catalog fills in as checks run, so it is complete after one full cycle.
#
# Precedence, highest first:
#   1. host environment variable -- an operator who exported it on the box made
#      an explicit local decision, and having the server silently outrank that
#      would make drift undebuggable. It shows up as source "host_env" so the
#      GUI can say why a workspace setting did not take on that host.
#   2. server override, pushed down on heartbeat ("server")
#   3. the default in the code ("default")
TUNABLE_OVERRIDES: dict[str, str] = {}
TUNABLE_CATALOG: dict[str, dict[str, Any]] = {}
TUNABLE_PREFIX = "ROOTTRACE_"

# Not every tunable is a threshold: the same env() path also reads database
# passwords, DSNs that embed credentials, and the collector's own API token.
# Those must never leave the host -- reporting their values would put live
# credentials in the collector document and on screen, and the server's
# redact_document cannot save us because it matches dict *keys* and these
# arrive as values. So the value is withheld here, at the source, and the
# server is not allowed to set them either: a credential belongs to the host,
# not to a workspace setting. URL/URI are in the pattern because a connection
# string routinely carries user:pass@; over-redacting a status URL costs a
# little insight, under-redacting a DSN leaks the database.
TUNABLE_SECRET_RE = re.compile(
    r"(PASSWORD|SECRET|TOKEN|KEY|CRED|AUTH|DSN|URI|URL)", re.IGNORECASE
)


def tunable_is_secret(name: str) -> bool:
    return bool(TUNABLE_SECRET_RE.search(name))


def _raw_tunable(name: str) -> tuple[str | None, str]:
    """(raw string or None, source) for one tunable name."""
    raw = os.environ.get(name)
    if raw is not None:
        return raw.strip(), "host_env"
    override = TUNABLE_OVERRIDES.get(name)
    if override is not None:
        return str(override).strip(), "server"
    return None, "default"


def _record_tunable(name: str, kind: str, default: Any, value: Any, source: str) -> None:
    if not name.startswith(TUNABLE_PREFIX):
        return
    TUNABLE_CATALOG[name] = {
        "type": kind,
        "default": default,
        "value": value,
        "source": source,
    }


def apply_server_tunables(mapping: Any) -> int:
    """Adopt server-set tunables. Returns how many were accepted.

    Names are prefix-checked because this is data from the network deciding how
    the collector behaves: without it a compromised or confused server could
    set PATH or LD_PRELOAD through the same channel. Values are kept as strings
    and parsed by the same accessors as everything else, so a bad value
    degrades to the code default rather than crashing a check.
    """
    if not isinstance(mapping, dict):
        return 0
    accepted: dict[str, str] = {}
    for name, value in mapping.items():
        key = str(name).strip()
        if not key.startswith(TUNABLE_PREFIX) or value is None:
            continue
        if tunable_is_secret(key):
            continue
        if isinstance(value, bool):
            accepted[key] = "true" if value else "false"
        else:
            accepted[key] = str(value).strip()
    TUNABLE_OVERRIDES.clear()
    TUNABLE_OVERRIDES.update(accepted)
    return len(accepted)


def tunable_report() -> list[dict[str, Any]]:
    """The catalog as the heartbeat reports it: what this collector read, what
    the code's default was, what is in effect, and which layer won.

    Secret-bearing tunables report only whether they are set and where from --
    never the value, and never a default that could be mistaken for one.
    """
    report: list[dict[str, Any]] = []
    for name, entry in sorted(TUNABLE_CATALOG.items()):
        if tunable_is_secret(name):
            report.append(
                {
                    "name": name,
                    "type": entry["type"],
                    "secret": True,
                    "configurable": False,
                    "is_set": entry["source"] != "default",
                    "source": entry["source"],
                }
            )
            continue
        report.append({"name": name, "secret": False, "configurable": True, **entry})
    return report


def env(name: str, default: str = "") -> str:
    raw, source = _raw_tunable(name)
    value = raw if raw is not None else default
    _record_tunable(name, "string", default, value, source)
    return value


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def split_csv(raw: str) -> list[str]:
    return [item.strip() for item in raw.split(",") if item.strip()]


def env_bool(name: str, default: bool = False) -> bool:
    raw, source = _raw_tunable(name)
    if not raw:
        value, source = default, "default"
    else:
        value = raw.lower() in {"1", "true", "yes", "y", "on"}
    _record_tunable(name, "bool", default, value, source)
    return value


def env_int(name: str, default: int) -> int:
    raw, source = _raw_tunable(name)
    value = default
    if raw:
        try:
            value = int(raw)
        except ValueError:
            source = "default"
    else:
        source = "default"
    _record_tunable(name, "int", default, value, source)
    return value


def env_float(name: str, default: float) -> float:
    raw, source = _raw_tunable(name)
    value = default
    if raw:
        try:
            value = float(raw)
        except ValueError:
            source = "default"
    else:
        source = "default"
    _record_tunable(name, "float", default, value, source)
    return value


def load_env_file(path: str | Path, *, override: bool = True) -> None:
    env_path = Path(path)
    try:
        lines = env_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise RuntimeError(f"could not read env file {env_path}: {exc}") from exc
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("export "):
            stripped = stripped[7:].strip()
        if "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            continue
        if not key.startswith("ROOTTRACE_") and key not in {"KUBECONFIG"}:
            continue
        value = value.strip()
        try:
            parts = shlex.split(value, comments=False, posix=True)
            value = " ".join(parts) if parts else ""
        except ValueError:
            value = value.strip().strip("'\"")
        if override or key not in os.environ:
            os.environ[key] = value


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            if any(part in str(key).lower() for part in SENSITIVE_KEYS):
                cleaned[key] = "[REDACTED]"
            else:
                cleaned[key] = redact(item)
        return cleaned
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def _redact_key_value(match: re.Match[str]) -> str:
    key, separator, secret = match.group(1), match.group(2), match.group(3)
    if len(secret) >= 2 and secret[0] in "\"'" and secret[-1] == secret[0]:
        return f"{key}{separator}{secret[0]}[REDACTED]{secret[0]}"
    return f"{key}{separator}[REDACTED]"


def redact_text(text: str) -> str:
    if "authorization:" in text.lower() or "bearer " in text.lower():
        return "[REDACTED]"
    redacted = text
    for pattern in SECRET_VALUE_PATTERNS:
        redacted = pattern.sub(
            lambda match: f"{match.group(1)}[REDACTED]" if match.groups() else "[REDACTED]",
            redacted,
        )
    return SENSITIVE_KEY_VALUE_RE.sub(_redact_key_value, redacted)


def auth_header(username: str, password: str) -> str:
    raw = f"{username}:{password}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def http_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = CHECK_TIMEOUT_SECONDS,
    context: ssl.SSLContext | None = None,
    method: str = "GET",
    data: bytes | None = None,
) -> Any:
    request = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
        raw = response.read().decode("utf-8", errors="replace")
        return json.loads(raw) if raw else {}


def http_text(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = CHECK_TIMEOUT_SECONDS,
    context: ssl.SSLContext | None = None,
    method: str = "GET",
    data: bytes | None = None,
) -> str:
    request = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
        return response.read().decode("utf-8", errors="replace")


def http_text_status(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = CHECK_TIMEOUT_SECONDS,
    context: ssl.SSLContext | None = None,
    method: str = "GET",
    data: bytes | None = None,
) -> tuple[int, str]:
    request = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            return response.status, response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")


class RootTraceClient:
    def __init__(self, api_url: str, token: str, timeout: int) -> None:
        self.api_url = api_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.context = ssl.create_default_context()

    def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(redact(payload), separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            f"{self.api_url}/{path.lstrip('/')}",
            data=body,
            headers={
                "Authorization": f"Collector {self.token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": f"roottrace-collector/{VERSION}",
                "Connection": "close",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                raw = response.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"RootTrace API returned HTTP {exc.code}: {detail}") from exc

    def post_ndjson(self, path: str, payloads: Iterable[dict[str, Any]]) -> dict[str, Any]:
        parsed = urlparse(self.api_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise RuntimeError("ROOTTRACE_API_URL must be an absolute http or https URL for streaming ingest.")
        target_path = f"{parsed.path.rstrip('/')}/{path.lstrip('/')}"
        if parsed.query:
            target_path = f"{target_path}?{parsed.query}"

        def chunks() -> Iterator[bytes]:
            for payload in payloads:
                yield (json.dumps(redact(payload), separators=(",", ":")) + "\n").encode("utf-8")

        connection_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        kwargs: dict[str, Any] = {"timeout": self.timeout}
        if parsed.scheme == "https":
            kwargs["context"] = self.context
        connection = connection_cls(parsed.netloc, **kwargs)
        try:
            connection.request(
                "POST",
                target_path,
                body=chunks(),
                headers={
                    "Authorization": f"Collector {self.token}",
                    "Content-Type": "application/x-ndjson",
                    "Accept": "application/json",
                    "User-Agent": f"roottrace-collector/{VERSION}",
                    "Connection": "close",
                },
                encode_chunked=True,
            )
            response = connection.getresponse()
            raw = response.read().decode("utf-8", errors="replace")
            if response.status < 200 or response.status >= 300:
                raise RuntimeError(f"RootTrace API returned HTTP {response.status}: {raw}")
            return json.loads(raw) if raw else {}
        finally:
            connection.close()


def proc_root() -> Path:
    return Path(env("ROOTTRACE_PROC_ROOT", "/proc"))


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def primary_ip() -> str | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.2)
            sock.connect(("1.1.1.1", 80))
            return sock.getsockname()[0]
    except OSError:
        return None


def read_first(path: Path) -> str | None:
    text = read_text(path).strip()
    return text or None


def sha256_short(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]


def ebs_volume_id(device_path: str) -> str | None:
    name = Path(os.path.realpath(device_path)).name
    raw = read_first(Path("/sys/class/block") / name / "device" / "serial")
    if not raw:
        return None
    raw = raw.lower()
    if raw.startswith("vol-"):
        return raw
    if raw.startswith("vol"):
        return f"vol-{raw[3:]}"
    return f"vol-{raw}"


def ec2_metadata(path: str, token: str | None = None) -> str | None:
    headers = {"X-aws-ec2-metadata-token": token} if token else {}
    try:
        return http_text(f"http://169.254.169.254/latest/{path.lstrip('/')}", headers=headers, timeout=0.5).strip()
    except Exception:
        return None


def ec2_json_metadata(path: str, token: str | None = None) -> dict[str, Any]:
    raw = ec2_metadata(path, token)
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def ec2_metadata_token() -> str | None:
    try:
        return http_text(
            "http://169.254.169.254/latest/api/token",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
            timeout=0.5,
            method="PUT",
        ).strip()
    except Exception:
        return None


def ec2_instance_tags(token: str | None) -> dict[str, str]:
    if not token:
        return {}
    raw_keys = ec2_metadata("meta-data/tags/instance", token)
    if not raw_keys:
        return {}
    tags: dict[str, str] = {}
    for key in raw_keys.splitlines():
        clean_key = key.strip()
        if not clean_key:
            continue
        value = ec2_metadata(f"meta-data/tags/instance/{quote(clean_key, safe='')}", token)
        if value is not None:
            tags[clean_key] = value
    return tags


def local_machine_identity() -> dict[str, Any]:
    machine_id = read_first(Path("/etc/machine-id")) or read_first(Path("/var/lib/dbus/machine-id"))
    interface_hashes = []
    net_root = Path("/sys/class/net")
    if net_root.exists():
        try:
            interfaces = sorted(net_root.iterdir())
        except OSError:
            interfaces = []
        for interface in interfaces:
            if interface.name == "lo":
                continue
            mac = read_first(interface / "address")
            if mac and mac != "00:00:00:00:00:00":
                interface_hashes.append(sha256_short(f"{interface.name}:{mac.lower()}"))
    return {
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "machine_id_hash": sha256_short(machine_id) if machine_id else None,
        "interface_hashes": interface_hashes[:8],
        "architecture": platform.machine(),
    }


def detect_provider() -> str:
    configured = env("ROOTTRACE_PROVIDER")
    if configured:
        return configured
    if env("KUBERNETES_SERVICE_HOST"):
        return "kubernetes"
    if Path("/.dockerenv").exists() or "docker" in read_text(Path("/proc/1/cgroup")).lower():
        return "docker"
    token = ec2_metadata_token()
    if token and ec2_metadata("meta-data/instance-id", token):
        return "ec2"
    return "bare_metal"


def detected_instance_id(provider: str) -> str | None:
    configured = env("ROOTTRACE_INSTANCE_ID")
    if configured:
        return configured
    if provider == "ec2":
        token = ec2_metadata_token()
        return ec2_metadata("meta-data/instance-id", token) if token else None
    return None


def host_payload() -> dict[str, Any]:
    hostname = env("ROOTTRACE_HOSTNAME", socket.gethostname())
    provider = detect_provider()
    token = ec2_metadata_token() if provider == "ec2" else None
    identity_document = ec2_json_metadata("dynamic/instance-identity/document", token) if token else {}
    aws_tags = ec2_instance_tags(token)
    local_identity = local_machine_identity()
    instance_id = detected_instance_id(provider)
    display_name = aws_tags.get("Name") or env("ROOTTRACE_HOST_LABEL") or hostname
    availability_zone = (
        identity_document.get("availabilityZone") or ec2_metadata("meta-data/placement/availability-zone", token)
        if token
        else None
    )
    instance_type = ec2_metadata("meta-data/instance-type", token) if token else None
    return {
        "hostname": hostname,
        "ip": primary_ip(),
        "provider": provider,
        "instance_id": instance_id,
        "tags": {
            "platform": platform.system(),
            "release": platform.release(),
            "architecture": platform.machine(),
            "collector_version": VERSION,
            "read_only": True,
            "streaming": env_bool("ROOTTRACE_STREAMING", False),
            "connection_model": "short_lived",
            "display_name": display_name,
            "identity_source": "aws_imds" if provider == "ec2" else "local_host",
            "machine_id_hash": local_identity.get("machine_id_hash"),
            "interface_hashes": local_identity.get("interface_hashes"),
            "fqdn": local_identity.get("fqdn"),
            "aws_tags": aws_tags,
            "aws_region": identity_document.get("region"),
            "aws_account_id": identity_document.get("accountId"),
            "aws_availability_zone": availability_zone,
            "aws_instance_type": instance_type,
        },
    }


def linux_audit_plugin_host_payload() -> dict[str, Any]:
    if not env_bool("ROOTTRACE_LINUX_AUDIT_PLUGIN_MINIMAL_HOST", True):
        return host_payload()
    hostname = env("ROOTTRACE_HOSTNAME", socket.gethostname())
    provider = env("ROOTTRACE_PROVIDER") or "auditd_plugin"
    display_name = env("ROOTTRACE_HOST_LABEL") or hostname
    return {
        "hostname": hostname,
        "ip": env("ROOTTRACE_HOST_IP") or None,
        "provider": provider,
        "instance_id": env("ROOTTRACE_INSTANCE_ID") or None,
        "tags": {
            "platform": platform.system(),
            "release": platform.release(),
            "architecture": platform.machine(),
            "collector_version": VERSION,
            "read_only": True,
            "streaming": env_bool("ROOTTRACE_STREAMING", False),
            "connection_model": "auditd_plugin",
            "display_name": display_name,
            "identity_source": "auditd_plugin_minimal",
        },
    }


def result(check_type: str, name: str, status: str, severity: str, message: str, evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "check_type": check_type,
        "name": name,
        "status": status,
        "severity": severity,
        "message": message,
        "evidence": redact(evidence),
        "observed_at": utc_now(),
    }


def linux_audit_enabled() -> bool:
    disabled = {item.lower() for item in split_csv(env("ROOTTRACE_DISABLED_CHECKS"))}
    if "linux_audit" in disabled:
        return False
    enabled = {item.lower() for item in split_csv(env("ROOTTRACE_ENABLED_CHECKS"))}
    if enabled:
        return "linux_audit" in enabled
    return env_bool("ROOTTRACE_LINUX_AUDIT_ENABLED", True)


def linux_audit_log_paths() -> list[Path]:
    configured = split_csv(env("ROOTTRACE_LINUX_AUDIT_LOG_PATHS", "/var/log/audit/audit.log"))
    return [Path(item) for item in configured]


def linux_audit_state_path() -> Path:
    configured = env("ROOTTRACE_LINUX_AUDIT_STATE_PATH")
    if configured:
        return Path(configured)
    state_dir = Path(env("ROOTTRACE_STATE_DIR", "/var/lib/roottrace-collector"))
    return state_dir / "linux_audit_offsets.json"


def parse_linux_audit_line(line: str) -> dict[str, Any]:
    record: dict[str, Any] = {}
    for key, value in LINUX_AUDIT_KV_RE.findall(line):
        record[key] = value.strip('"')
    msg_match = LINUX_AUDIT_MSG_RE.search(line)
    if msg_match:
        timestamp, _, serial = msg_match.group(1).rpartition(":")
        if timestamp and serial:
            try:
                record["audit_timestamp"] = float(timestamp)
            except ValueError:
                record["audit_timestamp_raw"] = timestamp
            record["audit_serial"] = serial
    record["raw_line"] = line
    return record


def _linux_audit_decode_hex_text(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text or len(text) % 2 or not re.fullmatch(r"[0-9A-Fa-f]+", text):
        return None
    try:
        decoded = bytes.fromhex(text).decode("utf-8", errors="replace")
    except ValueError:
        return None
    return " ".join(part for part in decoded.replace("\x00", " ").split() if part)


def _linux_audit_first_record(records_by_type: dict[str, Any], record_type: str) -> dict[str, Any]:
    value = records_by_type.get(record_type)
    if isinstance(value, list):
        return value[0] if value and isinstance(value[0], dict) else {}
    return value if isinstance(value, dict) else {}


def _linux_audit_records_for_type(records_by_type: dict[str, Any], record_type: str) -> list[dict[str, Any]]:
    value = records_by_type.get(record_type)
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        return [value]
    return []


def _linux_audit_event_time(timestamp: Any) -> str | None:
    try:
        return datetime.fromtimestamp(float(timestamp), timezone.utc).isoformat()
    except (TypeError, ValueError, OSError):
        return None


def _linux_audit_normalized_uid(value: Any) -> str | None:
    raw = str(value or "").strip().strip('"')
    if raw.lower() in LINUX_AUDIT_UNSET_UID_VALUES:
        return None
    try:
        uid_int = int(raw)
    except ValueError:
        return None
    if uid_int < 0 or uid_int == 4294967295:
        return None
    return str(uid_int)


def _linux_audit_name_domain(name: str | None) -> str | None:
    if not name:
        return None
    if "@" in name:
        domain = name.rsplit("@", 1)[-1].strip()
        return domain or None
    if "\\" in name:
        domain = name.split("\\", 1)[0].strip()
        return domain or None
    return None


def _linux_audit_resolve_uid(value: Any) -> dict[str, Any]:
    uid = _linux_audit_normalized_uid(value)
    if uid is None:
        return {"uid": str(value or ""), "is_unset": True, "identity_source": "unset"}
    cached = LINUX_AUDIT_UID_CACHE.get(uid)
    if cached is not None:
        return dict(cached)
    result: dict[str, Any] = {
        "uid": uid,
        "name": None,
        "domain": None,
        "is_unset": False,
        "identity_source": "unresolved",
    }
    if env_bool("ROOTTRACE_LINUX_AUDIT_RESOLVE_USERS", True) and pwd is not None:
        try:
            entry = pwd.getpwuid(int(uid))
            result.update(
                {
                    "name": entry.pw_name,
                    "domain": _linux_audit_name_domain(entry.pw_name),
                    "identity_source": "nss",
                }
            )
        except (KeyError, ValueError, OverflowError, OSError):
            pass
    cache_limit = max(env_int("ROOTTRACE_LINUX_AUDIT_UID_CACHE_SIZE", 4096), 64)
    if len(LINUX_AUDIT_UID_CACHE) >= cache_limit:
        LINUX_AUDIT_UID_CACHE.pop(next(iter(LINUX_AUDIT_UID_CACHE)))
    LINUX_AUDIT_UID_CACHE[uid] = dict(result)
    return result


def _linux_audit_clean_account(value: Any) -> str | None:
    account = str(value or "").strip().strip('"')
    if not account or account in {"(null)", "?", "unset"}:
        return None
    return account


def _linux_audit_identity_from_candidates(
    *,
    login_identity: dict[str, Any],
    user_identity: dict[str, Any],
    effective_identity: dict[str, Any],
    audit_account: str | None,
) -> dict[str, Any]:
    if not login_identity.get("is_unset"):
        uid = str(login_identity.get("uid") or "").strip()
        name = str(login_identity.get("name") or "").strip()
        label = name or (f"uid {uid}" if uid else "")
        if label:
            return {
                "type": "login",
                "uid": uid or None,
                "name": name or None,
                "domain": login_identity.get("domain"),
                "source": login_identity.get("identity_source"),
                "label": label,
            }
    if audit_account:
        return {
            "type": "account",
            "uid": None,
            "name": audit_account,
            "domain": _linux_audit_name_domain(audit_account),
            "source": "audit_account",
            "label": audit_account,
        }
    for identity_type, identity in (("uid", user_identity), ("euid", effective_identity)):
        if identity.get("is_unset"):
            continue
        uid = str(identity.get("uid") or "").strip()
        name = str(identity.get("name") or "").strip()
        label = name or (f"uid {uid}" if uid else "")
        if label:
            source = str(identity.get("identity_source") or "uid")
            return {
                "type": identity_type,
                "uid": uid or None,
                "name": name or None,
                "domain": identity.get("domain"),
                "source": f"{identity_type}_{source}",
                "label": label,
            }
    return {
        "type": "unknown",
        "uid": None,
        "name": None,
        "domain": None,
        "source": "unknown",
        "label": "unknown",
    }


def linux_audit_event_from_records(records: list[dict[str, Any]], *, source_path: str | None = None) -> dict[str, Any]:
    records_by_type: dict[str, Any] = {}
    raw_records: list[str] = []
    preserve_raw = env_bool("ROOTTRACE_LINUX_AUDIT_PRESERVE_RAW", True)
    max_raw_records = max(env_int("ROOTTRACE_LINUX_AUDIT_MAX_RAW_RECORDS", 64), 0)
    for record in records:
        record_type = str(record.get("type") or "UNKNOWN")
        clean_record = {key: value for key, value in record.items() if key != "raw_line"}
        existing = records_by_type.get(record_type)
        if existing is None:
            records_by_type[record_type] = clean_record
        elif isinstance(existing, list):
            existing.append(clean_record)
        else:
            records_by_type[record_type] = [existing, clean_record]
        if preserve_raw and len(raw_records) < max_raw_records and record.get("raw_line"):
            raw_records.append(str(record["raw_line"]))

    first = records[0] if records else {}
    syscall = _linux_audit_first_record(records_by_type, "SYSCALL")
    cwd = _linux_audit_first_record(records_by_type, "CWD")
    proctitle = _linux_audit_first_record(records_by_type, "PROCTITLE")
    path_records = _linux_audit_records_for_type(records_by_type, "PATH")
    user_records = [
        item
        for record_type in ("USER_LOGIN", "USER_AUTH", "USER_ACCT", "CRED_ACQ", "CRED_DISP", "USER_START", "USER_END")
        for item in _linux_audit_records_for_type(records_by_type, record_type)
    ]
    primary = syscall or (user_records[0] if user_records else first)
    command_line = _linux_audit_decode_hex_text(proctitle.get("proctitle"))
    path_names = [
        str(item.get("name"))
        for item in path_records
        if item.get("name") and str(item.get("name")) != "(null)"
    ]
    audit_keys = sorted(
        {
            str(record.get("key"))
            for record in records
            if record.get("key") and str(record.get("key")) != "(null)"
        }
    )
    audit_timestamp = first.get("audit_timestamp")
    success_value = str(primary.get("success") or "").lower()
    if success_value in {"yes", "1", "true"}:
        outcome = "success"
    elif success_value in {"no", "0", "false"}:
        outcome = "failure"
    else:
        outcome = "unknown"
    record_types = list(records_by_type.keys())
    login_identity = _linux_audit_resolve_uid(primary.get("auid"))
    user_identity = _linux_audit_resolve_uid(primary.get("uid"))
    effective_identity = _linux_audit_resolve_uid(primary.get("euid"))
    audit_account = _linux_audit_clean_account(primary.get("acct") or primary.get("account"))
    actor_identity = _linux_audit_identity_from_candidates(
        login_identity=login_identity,
        user_identity=user_identity,
        effective_identity=effective_identity,
        audit_account=audit_account,
    )
    event = {
        "audit_serial": str(first.get("audit_serial") or ""),
        "audit_timestamp": audit_timestamp,
        "event_time": _linux_audit_event_time(audit_timestamp),
        "record_types": record_types,
        "primary_type": record_types[0] if record_types else "UNKNOWN",
        "outcome": outcome,
        "actor_auid": primary.get("auid"),
        "actor_uid": primary.get("uid"),
        "actor_euid": primary.get("euid"),
        "actor_login_uid": None if login_identity.get("is_unset") else login_identity.get("uid"),
        "actor_login_name": login_identity.get("name"),
        "actor_login_domain": login_identity.get("domain"),
        "actor_login_identity_source": login_identity.get("identity_source"),
        "actor_login_uid_unset": bool(login_identity.get("is_unset")),
        "actor_user_name": user_identity.get("name"),
        "actor_effective_name": effective_identity.get("name"),
        "actor_account": audit_account,
        "actor_identity_type": actor_identity.get("type"),
        "actor_identity_uid": actor_identity.get("uid"),
        "actor_identity_name": actor_identity.get("name"),
        "actor_identity_domain": actor_identity.get("domain"),
        "actor_identity_source": actor_identity.get("source"),
        "actor_identity_label": actor_identity.get("label"),
        "session_id": primary.get("ses"),
        "pid": primary.get("pid"),
        "ppid": primary.get("ppid"),
        "syscall": primary.get("syscall"),
        "arch": primary.get("arch"),
        "subject_context": primary.get("subj"),
        "comm": primary.get("comm"),
        "executable": primary.get("exe"),
        "terminal": primary.get("tty") or primary.get("terminal"),
        "cwd": cwd.get("cwd"),
        "command_line": command_line,
        "path_names": path_names[:64],
        "audit_key": audit_keys[0] if audit_keys else None,
        "audit_keys": audit_keys[:32],
        "source_path": source_path,
        "records": records_by_type,
        "raw_records": raw_records,
    }
    if not event["audit_serial"]:
        event["audit_serial"] = sha256_short("|".join(raw_records) or json.dumps(records_by_type, sort_keys=True))
    return event


def load_linux_audit_state() -> dict[str, Any]:
    path = linux_audit_state_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"version": 1, "files": {}}
    if not isinstance(data, dict):
        return {"version": 1, "files": {}}
    files = data.get("files")
    if not isinstance(files, dict):
        data["files"] = {}
    return data


def save_linux_audit_state(state: dict[str, Any]) -> None:
    path = linux_audit_state_path()
    try:
        path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
        tmp = path.with_suffix(f".{os.getpid()}.tmp")
        tmp.write_text(json.dumps(state, separators=(",", ":")), encoding="utf-8")
        tmp.chmod(0o600)
        os.replace(tmp, path)
    except OSError as exc:
        LAST_LINUX_AUDIT_STATS["state_error"] = str(exc)


def _linux_audit_initial_offset(size: int) -> int:
    if env_bool("ROOTTRACE_LINUX_AUDIT_READ_FROM_BEGINNING", False):
        return 0
    lookback_bytes = max(env_int("ROOTTRACE_LINUX_AUDIT_INITIAL_LOOKBACK_BYTES", 1_048_576), 0)
    return max(0, size - lookback_bytes)


def read_linux_audit_lines(state: dict[str, Any]) -> tuple[list[tuple[str, str]], dict[str, Any]]:
    files_state = state.setdefault("files", {})
    if not isinstance(files_state, dict):
        files_state = {}
        state["files"] = files_state
    max_bytes = max(env_int("ROOTTRACE_LINUX_AUDIT_MAX_BYTES_PER_CYCLE", 4 * 1024 * 1024), 64 * 1024)
    max_lines = max(env_int("ROOTTRACE_LINUX_AUDIT_MAX_LINES_PER_CYCLE", 25_000), 100)
    max_line_bytes = max(env_int("ROOTTRACE_LINUX_AUDIT_MAX_LINE_BYTES", 64 * 1024), 4096)
    lines: list[tuple[str, str]] = []
    bytes_read = 0
    line_count = 0
    errors: list[str] = []

    for path in linux_audit_log_paths():
        path_key = str(path)
        try:
            stat_result = path.stat()
        except OSError as exc:
            errors.append(f"{path_key}: {exc}")
            continue
        previous = files_state.get(path_key) if isinstance(files_state.get(path_key), dict) else {}
        previous_inode = previous.get("inode")
        previous_device = previous.get("device")
        previous_offset = int(previous.get("offset") or 0)
        same_file = previous_inode == stat_result.st_ino and previous_device == stat_result.st_dev
        if same_file and 0 <= previous_offset <= stat_result.st_size:
            offset = previous_offset
        else:
            offset = _linux_audit_initial_offset(stat_result.st_size)
        try:
            with path.open("rb") as handle:
                handle.seek(offset)
                if offset > 0 and (not same_file or previous_offset != offset):
                    handle.readline(max_line_bytes + 1)
                while bytes_read < max_bytes and line_count < max_lines:
                    raw = handle.readline(max_line_bytes + 1)
                    if not raw:
                        break
                    bytes_read += len(raw)
                    line_count += 1
                    if len(raw) > max_line_bytes:
                        continue
                    line = raw.decode("utf-8", errors="replace").strip()
                    if line:
                        lines.append((path_key, line))
                files_state[path_key] = {
                    "device": stat_result.st_dev,
                    "inode": stat_result.st_ino,
                    "offset": handle.tell(),
                    "size": stat_result.st_size,
                    "updated_at": utc_now(),
                }
        except OSError as exc:
            errors.append(f"{path_key}: {exc}")
    LAST_LINUX_AUDIT_STATS.update(
        {
            "source_paths": [str(path) for path in linux_audit_log_paths()],
            "lines_read": line_count,
            "bytes_read": bytes_read,
            "read_errors": errors[:8],
            "last_read_at": utc_now(),
        }
    )
    return lines, state


def collect_linux_audit_events() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    state = load_linux_audit_state()
    lines, next_state = read_linux_audit_lines(state)
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    order: list[tuple[str, str, str]] = []
    parse_errors = 0
    for source_path, line in lines:
        record = parse_linux_audit_line(line)
        serial = str(record.get("audit_serial") or "")
        timestamp = str(record.get("audit_timestamp") or record.get("audit_timestamp_raw") or "")
        if not serial:
            serial = sha256_short(line)
        key = (source_path, timestamp, serial)
        if key not in grouped:
            grouped[key] = []
            order.append(key)
        if not record:
            parse_errors += 1
            continue
        grouped[key].append(record)
    events = [
        linux_audit_event_from_records(grouped[key], source_path=key[0])
        for key in order
        if grouped.get(key)
    ]
    LAST_LINUX_AUDIT_STATS.update(
        {
            "events_prepared": len(events),
            "parse_errors": parse_errors,
            "last_prepared_at": utc_now(),
        }
    )
    return events, next_state


def chunked(items: list[dict[str, Any]], size: int) -> Iterator[list[dict[str, Any]]]:
    batch_size = max(size, 1)
    for index in range(0, len(items), batch_size):
        yield items[index: index + batch_size]


def send_linux_audit_event_chunks(client: RootTraceClient, host: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any]:
    batch_size = max(env_int("ROOTTRACE_LINUX_AUDIT_BATCH_EVENTS", 250), 1)

    def payloads() -> Iterator[dict[str, Any]]:
        for batch in chunked(events, batch_size):
            yield {
                "host": host,
                "events": batch,
                "raw": {
                    "collector_version": VERSION,
                    "source": "linux_audit",
                    "batch_event_count": len(batch),
                    "read_only": True,
                },
            }

    def post_json_batches(*, streaming_error: str | None = None) -> dict[str, Any]:
        totals: dict[str, Any] = {"payload_count": 0, "events_created": 0, "duplicates": 0}
        if streaming_error:
            totals["streaming_error"] = streaming_error[:500]
        for payload in payloads():
            response = client.post("collectors/linux-audit/ingest", payload)
            totals["payload_count"] += 1
            totals["events_created"] += int(response.get("events_created", 0))
            totals["duplicates"] += int(response.get("duplicates", 0))
        return totals

    if not env_bool("ROOTTRACE_LINUX_AUDIT_STREAMING", False):
        return post_json_batches()
    try:
        return client.post_ndjson("collectors/linux-audit/ingest/stream", payloads())
    except RuntimeError as exc:
        return post_json_batches(streaming_error=str(exc))


def linux_audit_plugin_debug_enabled() -> bool:
    return env_bool("ROOTTRACE_LINUX_AUDIT_PLUGIN_DEBUG", False)


def send_linux_audit(client: RootTraceClient, host: dict[str, Any]) -> None:
    if not linux_audit_enabled():
        return
    events, next_state = collect_linux_audit_events()
    if not events:
        save_linux_audit_state(next_state)
        LAST_LINUX_AUDIT_STATS.update({"events_sent": 0, "last_sent_at": utc_now()})
        return
    response = send_linux_audit_event_chunks(client, host, events)
    save_linux_audit_state(next_state)
    LAST_LINUX_AUDIT_STATS.update(
        {
            "events_sent": len(events),
            "api_response": response,
            "last_error": None,
            "last_sent_at": utc_now(),
        }
    )



# --- Query-level database statistics ----------------------------------------
#
# The database health checks answer "is it healthy"; these answer the question
# that always follows, "which query is doing this". Read-only, from the
# engine's own statistics view, and never the literal SQL: every view here
# normalises parameters out before the collector sees anything, which is what
# makes the digest safe to ship. Enable with ROOTTRACE_DB_QUERY_STATS=true.


def db_query_stats_enabled() -> bool:
    return env_bool("ROOTTRACE_DB_QUERY_STATS", False)


def db_query_statement_limit() -> int:
    # Enough to find the expensive ones; small enough that a busy server does
    # not ship thousands of shapes every interval.
    return max(1, min(env_int("ROOTTRACE_DB_QUERY_STATS_LIMIT", 100), 500))


def collect_postgres_query_stats() -> list[dict[str, Any]]:
    """pg_stat_statements, already normalised by the extension.

    A missing extension is not an error worth alerting on -- it is simply not
    installed -- so it degrades to no statements rather than a failed check.
    """
    targets = postgres_targets()
    if not targets:
        return []
    try:
        import psycopg  # type: ignore
    except Exception:
        try:
            import psycopg2 as psycopg  # type: ignore
        except Exception:
            return []
    limit = db_query_statement_limit()
    timeout = env_int("ROOTTRACE_POSTGRES_TIMEOUT_SECONDS", int(CHECK_TIMEOUT_SECONDS))
    payloads: list[dict[str, Any]] = []
    for target in targets:
        statements: list[dict[str, Any]] = []
        try:
            with psycopg.connect(target["dsn"], connect_timeout=timeout) as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT d.datname, s.query, s.calls, s.total_exec_time, s.rows
                        FROM pg_stat_statements s
                        JOIN pg_database d ON d.oid = s.dbid
                        ORDER BY s.total_exec_time DESC
                        LIMIT %s
                        """,
                        (limit,),
                    )
                    for database_name, query, calls, total_ms, rows in cursor.fetchall():
                        statements.append(
                            {
                                "statement": query or "",
                                "database": database_name,
                                "calls": float(calls or 0),
                                "total_ms": float(total_ms or 0),
                                "rows": float(rows or 0),
                            }
                        )
        except Exception as exc:
            LAST_DB_QUERY_STATS["last_error"] = f"postgres: {exc}"[:500]
            continue
        if statements:
            payloads.append(
                {
                    "engine": "postgres",
                    "host": target.get("safe_target") or "postgres",
                    "instance": target.get("database"),
                    "statements": statements,
                }
            )
    return payloads


def collect_mysql_query_stats() -> list[dict[str, Any]]:
    """performance_schema digest summary, normalised by the server."""
    targets = mysql_targets() if "mysql_targets" in globals() else []
    if not targets:
        return []
    try:
        import mysql.connector  # type: ignore
    except Exception:
        return []
    limit = db_query_statement_limit()
    payloads: list[dict[str, Any]] = []
    for target in targets:
        statements: list[dict[str, Any]] = []
        try:
            connection = mysql.connector.connect(**target["params"])
            try:
                cursor = connection.cursor()
                cursor.execute(
                    """
                    SELECT SCHEMA_NAME, DIGEST_TEXT, COUNT_STAR,
                           SUM_TIMER_WAIT/1000000000 AS total_ms, SUM_ROWS_SENT
                    FROM performance_schema.events_statements_summary_by_digest
                    WHERE DIGEST_TEXT IS NOT NULL
                    ORDER BY SUM_TIMER_WAIT DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
                for schema, digest_text, calls, total_ms, rows in cursor.fetchall():
                    statements.append(
                        {
                            "statement": digest_text or "",
                            "database": schema,
                            "calls": float(calls or 0),
                            "total_ms": float(total_ms or 0),
                            "rows": float(rows or 0),
                        }
                    )
                cursor.close()
            finally:
                connection.close()
        except Exception as exc:
            LAST_DB_QUERY_STATS["last_error"] = f"mysql: {exc}"[:500]
            continue
        if statements:
            payloads.append(
                {
                    "engine": "mysql",
                    "host": target.get("safe_target") or "mysql",
                    "statements": statements,
                }
            )
    return payloads



def collect_mongodb_query_stats() -> list[dict[str, Any]]:
    """Per-collection operation counters, from the `top` admin command.

    MongoDB has no pg_stat_statements. The profiler (system.profile) records
    individual operations, but it is off by default, costs writes to enable,
    and is a capped sample rather than a counter -- which is the wrong shape
    for a pipeline that stores deltas between snapshots.

    `top` is the counter that does exist: cumulative call counts and
    microseconds per namespace and operation, since the server started,
    available on a stock deployment with no profiling turned on. A restart
    resets it backwards, which the server already reads as a gap rather than a
    negative spike.

    The unit of cost is therefore "readLock on app.users", not a query shape.
    That is coarser than the SQL engines and it is what the database actually
    exposes; naming the namespace still answers which collection is expensive.
    """
    uri = env("ROOTTRACE_MONGODB_URI")
    targets = [uri] if uri else split_csv(env("ROOTTRACE_MONGODB_TARGETS"))
    if not targets:
        return []
    try:
        from pymongo import MongoClient  # type: ignore
    except Exception:
        return []

    limit = db_query_statement_limit()
    timeout = env_int("ROOTTRACE_MONGODB_TIMEOUT_MS", 2000)
    payloads: list[dict[str, Any]] = []
    for raw in targets:
        statements: list[dict[str, Any]] = []
        try:
            client = MongoClient(raw, serverSelectionTimeoutMS=timeout)
            try:
                # `top` is a mongod command. A URI pointing at mongos -- which
                # is what a sharded deployment hands out -- answers
                # CommandNotFound, and the router keeps no per-namespace timing
                # of its own to fall back to. Say so plainly instead of letting
                # a bare "no such cmd: top" reach the operator, and skip rather
                # than shipping call counts with no durations: the whole page
                # ranks by time, so timing-less rows would sort arbitrarily and
                # read as "nothing is slow".
                if (client.admin.command("hello") or {}).get("msg") == "isdbgrid":
                    LAST_DB_QUERY_STATS["last_error"] = (
                        "mongodb: per-namespace query stats need a direct mongod "
                        "connection; this URI points at mongos, which does not "
                        "implement top. Point ROOTTRACE_MONGODB_URI at a replica "
                        "set member to collect them."
                    )
                    continue
                totals = (client.admin.command("top") or {}).get("totals") or {}
                for namespace, entry in totals.items():
                    if namespace == "note" or not isinstance(entry, dict):
                        continue
                    for operation, counters in entry.items():
                        if not isinstance(counters, dict):
                            continue
                        calls = float(counters.get("count") or 0)
                        if calls <= 0:
                            continue
                        statements.append(
                            {
                                # The "statement" is the operation against the
                                # namespace. Never a query document: those carry
                                # the values a user searched for.
                                "statement": f"{operation} {namespace}",
                                "database": namespace.split(".", 1)[0],
                                "calls": calls,
                                "total_ms": float(counters.get("time") or 0) / 1000.0,
                                "rows": 0.0,
                            }
                        )
            finally:
                client.close()
        except Exception as exc:
            LAST_DB_QUERY_STATS["last_error"] = f"mongodb: {exc}"[:500]
            continue
        statements.sort(key=lambda row: row["total_ms"], reverse=True)
        if statements:
            payloads.append(
                {
                    "engine": "mongodb",
                    "host": redact_url_credentials(raw),
                    "statements": statements[:limit],
                }
            )
    return payloads


def collect_elasticsearch_query_stats() -> list[dict[str, Any]]:
    """Per-index search counters, from _stats/search.

    Elasticsearch has no per-shape statistics view either. The slow log records
    individual queries, but it is sampled by threshold and would need parsing
    off disk. `_stats/search` gives what this pipeline wants: query_total and
    query_time_in_millis per index, cumulative since the index opened.

    So the cost is attributed to an index rather than a query shape. That still
    answers which index is absorbing the search time, which is the question
    asked of a cluster.
    """
    urls = split_csv(env("ROOTTRACE_ELASTICSEARCH_URLS") or env("ROOTTRACE_ELASTICSEARCH_URL"))
    if not urls:
        return []
    headers = {}
    username = env("ROOTTRACE_ELASTICSEARCH_USERNAME")
    password = env("ROOTTRACE_ELASTICSEARCH_PASSWORD")
    if username or password:
        headers["Authorization"] = auth_header(username, password)

    limit = db_query_statement_limit()
    payloads: list[dict[str, Any]] = []
    for raw_url in urls:
        base_url = raw_url.rstrip("/")
        statements: list[dict[str, Any]] = []
        try:
            stats = http_json(f"{base_url}/_stats/search", headers=headers) or {}
            for index_name, entry in (stats.get("indices") or {}).items():
                search = ((entry.get("total") or {}).get("search") or {})
                calls = float(search.get("query_total") or 0)
                if calls <= 0:
                    continue
                statements.append(
                    {
                        "statement": f"search {index_name}",
                        "database": index_name,
                        "calls": calls,
                        "total_ms": float(search.get("query_time_in_millis") or 0),
                        # Documents returned is not exposed per index; fetch
                        # count is the closest honest number and is reported as
                        # itself rather than dressed up as rows.
                        "rows": 0.0,
                    }
                )
        except Exception as exc:
            LAST_DB_QUERY_STATS["last_error"] = f"elasticsearch: {exc}"[:500]
            continue
        statements.sort(key=lambda row: row["total_ms"], reverse=True)
        if statements:
            payloads.append(
                {
                    "engine": "elasticsearch",
                    "host": redact_url_credentials(base_url),
                    "statements": statements[:limit],
                }
            )
    return payloads


LAST_DB_QUERY_STATS: dict[str, Any] = {"sent": 0, "last_error": None, "last_sent_at": None}


def send_db_query_stats(client: RootTraceClient) -> None:
    """Ship one counter snapshot per engine. Never raises into the run loop."""
    if not db_query_stats_enabled():
        return
    payloads: list[dict[str, Any]] = []
    try:
        payloads.extend(collect_postgres_query_stats())
        payloads.extend(collect_mysql_query_stats())
        payloads.extend(collect_mongodb_query_stats())
        payloads.extend(collect_elasticsearch_query_stats())
    except Exception as exc:
        LAST_DB_QUERY_STATS["last_error"] = str(exc)[:500]
        return
    sent = 0
    for payload in payloads:
        try:
            payload["observed_at"] = utc_now()
            client.post("collectors/db-queries", payload)
            sent += len(payload.get("statements") or [])
        except Exception as exc:
            LAST_DB_QUERY_STATS["last_error"] = str(exc)[:500]
    LAST_DB_QUERY_STATS.update({"sent": sent, "last_sent_at": utc_now()})

def run_linux_audit_stdin_plugin(client: RootTraceClient) -> int:
    host = linux_audit_plugin_host_payload()
    current_key: tuple[str, str] | None = None
    current_records: list[dict[str, Any]] = []
    pending_events: list[dict[str, Any]] = []
    batch_size = max(env_int("ROOTTRACE_LINUX_AUDIT_BATCH_EVENTS", 250), 1)
    flush_seconds = max(env_float("ROOTTRACE_LINUX_AUDIT_PLUGIN_FLUSH_SECONDS", 2.0), 0.1)
    last_flush = time.monotonic()
    debug = linux_audit_plugin_debug_enabled()

    def flush_current() -> None:
        nonlocal current_key, current_records, pending_events
        if current_records:
            pending_events.append(linux_audit_event_from_records(current_records, source_path="auditd-plugin-stdin"))
        current_key = None
        current_records = []

    def flush_pending() -> None:
        nonlocal pending_events, last_flush
        if not pending_events:
            last_flush = time.monotonic()
            return
        events = pending_events
        pending_events = []
        try:
            response = send_linux_audit_event_chunks(client, host, events)
            if debug:
                print(
                    f"{utc_now()} Linux audit plugin sent {len(events)} event(s): {response}",
                    file=sys.stderr,
                    flush=True,
                )
            LAST_LINUX_AUDIT_STATS.update(
                {
                    "plugin_events_sent": len(events),
                    "plugin_api_response": response,
                    "plugin_last_error": None,
                    "plugin_last_sent_at": utc_now(),
                }
            )
        except Exception as exc:
            pending_events = events + pending_events
            LAST_LINUX_AUDIT_STATS.update(
                {
                    "plugin_last_error": str(exc),
                    "plugin_pending_events": len(pending_events),
                    "plugin_last_error_at": utc_now(),
                }
            )
            print(f"{utc_now()} Linux audit plugin ingest failed: {exc}", file=sys.stderr, flush=True)
        last_flush = time.monotonic()

    def process_line(raw_line: str) -> None:
        nonlocal current_key, current_records
        line = raw_line.strip()
        if not line:
            return
        record = parse_linux_audit_line(line)
        key = (
            str(record.get("audit_timestamp") or record.get("audit_timestamp_raw") or ""),
            str(record.get("audit_serial") or sha256_short(line)),
        )
        if current_key is not None and key != current_key:
            flush_current()
        current_key = key
        current_records.append(record)
        if len(pending_events) >= batch_size or time.monotonic() - last_flush >= flush_seconds:
            flush_current()
            flush_pending()

    try:
        import select

        if debug:
            print(
                f"{utc_now()} Linux audit plugin started with flush_seconds={flush_seconds} batch_size={batch_size}",
                file=sys.stderr,
                flush=True,
            )

        while True:
            ready, _, _ = select.select([sys.stdin], [], [], flush_seconds)
            if ready:
                raw_line = sys.stdin.readline()
                if raw_line == "":
                    flush_current()
                    flush_pending()
                    time.sleep(flush_seconds)
                    continue
                process_line(raw_line)
            elif time.monotonic() - last_flush >= flush_seconds:
                flush_current()
                flush_pending()
    except (ImportError, OSError, TypeError, ValueError):
        for raw_line in sys.stdin:
            process_line(raw_line)
            if pending_events:
                flush_pending()
    flush_current()
    flush_pending()
    return 0


def check_linux_audit() -> list[dict[str, Any]]:
    if not linux_audit_enabled():
        return []
    if platform.system().lower() != "linux":
        return [
            result(
                "linux_audit",
                "Linux audit ingestion",
                "unknown",
                "low",
                "Linux audit ingestion is enabled, but this host is not reporting a Linux platform.",
                {"platform": platform.platform(), "enabled": True},
            )
        ]
    paths = linux_audit_log_paths()
    existing = [str(path) for path in paths if path.exists()]
    readable = [str(path) for path in paths if path.exists() and os.access(path, os.R_OK)]
    stats = dict(LAST_LINUX_AUDIT_STATS)
    if readable:
        status_value = "pass"
        message = f"Linux audit ingestion is enabled for {len(readable)} readable audit log source(s)."
    elif existing:
        status_value = "unknown"
        message = "Linux audit logs exist, but the collector could not read them with current permissions."
    else:
        status_value = "unknown"
        message = "Linux audit ingestion is enabled, but no audit log file was found yet."
    return [
        result(
            "linux_audit",
            "Linux audit ingestion",
            status_value,
            "low",
            message,
            {
                "enabled": True,
                "source_paths": [str(path) for path in paths],
                "existing_paths": existing,
                "readable_paths": readable,
                "state_path": str(linux_audit_state_path()),
                "batch_events": env_int("ROOTTRACE_LINUX_AUDIT_BATCH_EVENTS", 250),
                "streaming": env_bool("ROOTTRACE_LINUX_AUDIT_STREAMING", False),
                "max_bytes_per_cycle": env_int("ROOTTRACE_LINUX_AUDIT_MAX_BYTES_PER_CYCLE", 4 * 1024 * 1024),
                "last_stats": stats,
            },
        )
    ]


def custom_metric_key(name: Any) -> str:
    raw = str(name or "").strip().lower()
    normalized = re.sub(r"[^a-z0-9_.-]+", "_", raw).strip("._-")
    normalized = re.sub(r"_+", "_", normalized)
    if normalized:
        return normalized[:96]
    return f"metric_{sha256_short(str(name))[:12]}"


def custom_metric_status(
    value: float,
    warn: float | int | None,
    fail: float | int | None,
    *,
    higher_is_worse: bool,
) -> tuple[str, str]:
    if higher_is_worse:
        if fail is not None and value >= float(fail):
            return "fail", "high"
        if warn is not None and value >= float(warn):
            return "warn", "medium"
    else:
        if fail is not None and value <= float(fail):
            return "fail", "high"
        if warn is not None and value <= float(warn):
            return "warn", "medium"
    return "pass", "low"


def first_not_none(*values: Any) -> Any:
    for value in values:
        if value is not None:
            return value
    return None


def threshold_value_from_mapping(item: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        if key in item and item[key] is not None:
            return item[key]
    return None


def normalize_custom_metric_status(status: Any) -> str | None:
    raw = str(status or "").strip().lower()
    if raw == "warning":
        return "warn"
    if raw == "error":
        return "fail"
    return raw if raw in VALID_RESULT_STATUSES else None


def canonical_custom_metric_thresholds(thresholds: dict[str, Any]) -> dict[str, Any]:
    canonical = dict(thresholds)
    warn = threshold_value_from_mapping(canonical, WARNING_THRESHOLD_KEYS)
    fail = threshold_value_from_mapping(canonical, ERROR_THRESHOLD_KEYS)
    if warn is not None:
        canonical["warn"] = warn
    if fail is not None:
        canonical["fail"] = fail
    return canonical


def canonical_custom_metric_evidence(evidence: Any) -> dict[str, Any]:
    clean = evidence if isinstance(evidence, dict) else {}
    thresholds = clean.get("thresholds")
    if not isinstance(thresholds, dict):
        return clean
    normalized = dict(clean)
    normalized["thresholds"] = canonical_custom_metric_thresholds(thresholds)
    return normalized


def custom_metric_result(
    name: str,
    value: float | int,
    *,
    check: str | None = None,
    check_label: str | None = None,
    label: str | None = None,
    unit: str = "",
    warn: float | int | None = None,
    fail: float | int | None = None,
    warning: float | int | None = None,
    error: float | int | None = None,
    warn_threshold: float | int | None = None,
    fail_threshold: float | int | None = None,
    warning_threshold: float | int | None = None,
    error_threshold: float | int | None = None,
    higher_is_worse: bool = True,
    status: str | None = None,
    severity: str | None = None,
    message: str | None = None,
    service: str | None = None,
    service_type: str | None = None,
    resource: str | None = None,
    resource_label: str = "Custom resource",
    details: dict[str, Any] | None = None,
    source: str | None = None,
) -> dict[str, Any]:
    if isinstance(value, bool):
        raise ValueError("custom metric value must be numeric, not boolean")
    numeric_value = float(value)
    if not math.isfinite(numeric_value):
        raise ValueError("custom metric value must be finite")
    warn = first_not_none(warn, warning, warn_threshold, warning_threshold)
    fail = first_not_none(fail, error, fail_threshold, error_threshold)
    metric_key = custom_metric_key(name)
    metric_label = (
        label or str(name).replace("_", " ").replace(".", " ").title()
    ).strip()
    raw_check = str(check).removeprefix("custom.") if check else str(name)
    check_key = custom_metric_key(raw_check)
    check_display = (
        check_label
        or (
            str(check).removeprefix("custom.").replace("_", " ").replace(".", " ").title()
            if check
            else metric_label
        )
    ).strip()
    metric_status, metric_severity = custom_metric_status(
        numeric_value,
        warn,
        fail,
        higher_is_worse=higher_is_worse,
    )
    status_alias = normalize_custom_metric_status(status)
    if status_alias:
        metric_status = status_alias
        metric_severity = {
            "fail": "high",
            "warn": "medium",
            "unknown": "medium",
            "pass": "low",
        }.get(metric_status, metric_severity)
    metric_severity = severity if severity in VALID_RESULT_SEVERITIES else metric_severity
    metric_resource = (resource or metric_label).strip()
    evidence = with_thresholds(
        {
            "custom_metric": True,
            "check_key": check_key,
            "check_label": check_display,
            "metric_key": metric_key,
            "metric_name": str(name),
            "metric_label": metric_label,
            "metric_value": round(numeric_value, 4),
            "unit": unit,
            "resource": metric_resource,
            "resource_label": resource_label or "Custom resource",
            "source": source,
            "details": redact(details or {}),
        },
        metric="metric_value",
        label=metric_label,
        unit=unit,
        warn=warn,
        fail=fail,
        higher_is_worse=higher_is_worse,
    )
    display_unit = unit if unit.startswith("%") else f" {unit}" if unit else ""
    custom = result(
        f"custom.{check_key}",
        f"{check_display}: {metric_label}" if check else f"{metric_label} custom metric",
        metric_status,
        metric_severity,
        message or f"{metric_label} is {round(numeric_value, 4)}{display_unit}.",
        evidence,
    )
    if service:
        custom["service"] = service
    if service_type:
        custom["service_type"] = service_type
    return custom


def _normalize_custom_metric_mapping(item: dict[str, Any], *, source: str) -> list[dict[str, Any]]:
    if {"check_type", "name", "status", "evidence"}.issubset(item):
        check_type = str(item.get("check_type") or "custom")
        if not check_type.startswith("custom."):
            check_type = f"custom.{custom_metric_key(check_type)}"
        status_value = str(item.get("status") or "unknown")
        status_alias = normalize_custom_metric_status(status_value)
        severity_value = str(item.get("severity") or "medium")
        normalized = result(
            check_type,
            str(item.get("name") or check_type),
            status_alias or "unknown",
            severity_value if severity_value in VALID_RESULT_SEVERITIES else "medium",
            str(item.get("message") or item.get("name") or check_type),
            canonical_custom_metric_evidence(item.get("evidence")),
        )
        for key in ("service", "service_type"):
            if item.get(key):
                normalized[key] = str(item[key])
        return [normalized]

    if "metrics" in item and isinstance(item["metrics"], list):
        checks: list[dict[str, Any]] = []
        inherited = {
            key: item[key]
            for key in (
                "check",
                "check_type",
                "check_label",
                "service",
                "service_type",
                "resource",
                "resource_label",
                "unit",
                "warn",
                "fail",
                "warning",
                "error",
                "warn_threshold",
                "fail_threshold",
                "warning_threshold",
                "error_threshold",
                "higher_is_worse",
            )
            if key in item and item[key] is not None
        }
        if isinstance(item.get("details"), dict):
            inherited["details"] = item["details"]
        for metric in item["metrics"]:
            if isinstance(metric, dict):
                checks.extend(
                    _normalize_custom_metric_mapping({**inherited, **metric}, source=source)
                )
        return checks

    if "name" in item and "value" in item:
        return [
            custom_metric_result(
                str(item["name"]),
                item["value"],
                check=(
                    str(item.get("check") or item.get("check_type"))
                    if item.get("check") or item.get("check_type")
                    else None
                ),
                check_label=str(item["check_label"]) if item.get("check_label") else None,
                label=str(item["label"]) if item.get("label") else None,
                unit=str(item.get("unit") or ""),
                warn=threshold_value_from_mapping(item, WARNING_THRESHOLD_KEYS),
                fail=threshold_value_from_mapping(item, ERROR_THRESHOLD_KEYS),
                higher_is_worse=item.get("higher_is_worse", True) is not False,
                status=str(item["status"]) if item.get("status") else None,
                severity=str(item["severity"]) if item.get("severity") else None,
                message=str(item["message"]) if item.get("message") else None,
                service=str(item["service"]) if item.get("service") else None,
                service_type=str(item["service_type"]) if item.get("service_type") else None,
                resource=str(item["resource"]) if item.get("resource") else None,
                resource_label=str(item.get("resource_label") or "Custom resource"),
                details=item.get("details") if isinstance(item.get("details"), dict) else None,
                source=source,
            )
        ]
    return []


def normalize_custom_metric_output(output: Any, *, source: str) -> list[dict[str, Any]]:
    if output is None:
        return []
    if isinstance(output, dict):
        if "name" in output or "metrics" in output or "check_type" in output:
            return _normalize_custom_metric_mapping(output, source=source)
        checks: list[dict[str, Any]] = []
        for name, value in output.items():
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                checks.append(custom_metric_result(str(name), value, source=source))
        return checks
    if isinstance(output, list) or isinstance(output, tuple):
        checks: list[dict[str, Any]] = []
        for item in output:
            checks.extend(normalize_custom_metric_output(item, source=source))
        return checks
    return []


def with_thresholds(
    evidence: dict[str, Any],
    *,
    metric: str,
    label: str,
    unit: str,
    warn: float | int | None,
    fail: float | int | None,
    higher_is_worse: bool = True,
) -> dict[str, Any]:
    enriched = dict(evidence)
    enriched["thresholds"] = {
        "metric": metric,
        "label": label,
        "unit": unit,
        "warn": warn,
        "fail": fail,
        "higher_is_worse": higher_is_worse,
    }
    return enriched


def threshold_status(percent: float, warn: float, fail: float) -> tuple[str, str]:
    if percent >= fail:
        return "fail", "critical"
    if percent >= warn:
        return "warn", "medium"
    return "pass", "low"


def worse_health(left: tuple[str, str], right: tuple[str, str]) -> tuple[str, str]:
    rank = {"pass": 0, "unknown": 1, "warn": 2, "fail": 3}
    return right if rank.get(right[0], 1) > rank.get(left[0], 1) else left


def ignored_disk_path(path: str) -> bool:
    normalized = os.path.normpath(path)
    for ignored in IGNORED_DISK_PATHS:
        if normalized == ignored or normalized.startswith(f"{ignored}/"):
            return True
    for prefix in IGNORED_DISK_PATH_PREFIXES:
        if normalized == prefix or normalized.startswith(f"{prefix}/"):
            return True
    return False


def disk_paths() -> list[str]:
    explicit = split_csv(env("ROOTTRACE_DISK_PATHS"))
    if explicit:
        return [path for path in explicit if not ignored_disk_path(path)]
    mounts = []
    mounts_path = proc_root() / "mounts"
    for line in read_text(mounts_path).splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[2] in PSEUDO_FILESYSTEMS:
            continue
        mount = parts[1].replace("\\040", " ")
        if ignored_disk_path(mount):
            continue
        mounts.append(mount)
    return sorted(set(mounts or ["/"]))


def mount_devices() -> dict[str, str]:
    devices: dict[str, str] = {}
    for line in read_text(proc_root() / "mounts").splitlines():
        parts = line.split()
        if len(parts) >= 2:
            devices[parts[1].replace("\\040", " ")] = parts[0]
    return devices


def check_disk() -> list[dict[str, Any]]:
    warn = env_float("ROOTTRACE_DISK_WARN_PERCENT", 80.0)
    fail = env_float("ROOTTRACE_DISK_FAIL_PERCENT", 90.0)
    checks = []
    devices = mount_devices()
    for path in disk_paths():
        try:
            usage = shutil.disk_usage(path)
        except OSError as exc:
            checks.append(result("disk", f"Disk usage {path}", "unknown", "low", f"Could not read disk usage for {path}.", {"error": str(exc), "path": path}))
            continue
        percent = 0.0 if usage.total == 0 else round((usage.used / usage.total) * 100, 2)
        status, severity = threshold_status(percent, warn, fail)
        checks.append(
            result(
                "disk",
                f"Disk usage {path}",
                status,
                severity,
                f"Disk usage on {path} is {percent}%.",
                with_thresholds(
                    {
                    "path": path,
                    "device": devices.get(path),
                    "volume_id": ebs_volume_id(devices[path]) if path in devices and devices[path].startswith("/dev/") else None,
                    "total_bytes": usage.total,
                    "used_bytes": usage.used,
                    "free_bytes": usage.free,
                    "used_percent": percent,
                    },
                    metric="used_percent",
                    label="Disk used",
                    unit="%",
                    warn=warn,
                    fail=fail,
                ),
            )
        )
    return checks


def check_inode_usage() -> list[dict[str, Any]]:
    warn = env_float("ROOTTRACE_INODE_WARN_PERCENT", 80.0)
    fail = env_float("ROOTTRACE_INODE_FAIL_PERCENT", 90.0)
    checks: list[dict[str, Any]] = []
    for path in disk_paths():
        try:
            stats = os.statvfs(path)
        except OSError as exc:
            checks.append(
                result(
                    "inode",
                    f"Inode usage {path}",
                    "unknown",
                    "low",
                    f"Could not read inode usage for {path}.",
                    {"path": path, "error": str(exc)},
                )
            )
            continue
        total = int(stats.f_files or 0)
        free = int(stats.f_ffree or 0)
        if total <= 0:
            continue
        used = max(0, total - free)
        percent = round((used / total) * 100, 2)
        status, severity = threshold_status(percent, warn, fail)
        checks.append(
            result(
                "inode",
                f"Inode usage {path}",
                status,
                severity,
                f"Inode usage on {path} is {percent}%.",
                with_thresholds(
                    {
                        "path": path,
                        "total_inodes": total,
                        "used_inodes": used,
                        "free_inodes": free,
                        "used_percent": percent,
                    },
                    metric="used_percent",
                    label="Inodes used",
                    unit="%",
                    warn=warn,
                    fail=fail,
                ),
            )
        )
    return checks


def diskstat_snapshot() -> dict[str, dict[str, int]]:
    devices: dict[str, dict[str, int]] = {}
    ignored_prefixes = ("loop", "ram", "fd", "sr")
    for line in read_text(proc_root() / "diskstats").splitlines():
        parts = line.split()
        if len(parts) < 14:
            continue
        name = parts[2]
        if name.startswith(ignored_prefixes):
            continue
        try:
            devices[name] = {
                "reads_completed": int(parts[3]),
                "sectors_read": int(parts[5]),
                "read_ms": int(parts[6]),
                "writes_completed": int(parts[7]),
                "sectors_written": int(parts[9]),
                "write_ms": int(parts[10]),
                "ios_in_progress": int(parts[11]),
                "io_ms": int(parts[12]),
                "weighted_io_ms": int(parts[13]),
            }
        except ValueError:
            continue
    return devices


def check_disk_io() -> list[dict[str, Any]]:
    sample_seconds = env_float("ROOTTRACE_DISK_IO_SAMPLE_SECONDS", 0.25)
    warn_util = env_float("ROOTTRACE_DISK_IO_WARN_UTIL_PERCENT", 80.0)
    fail_util = env_float("ROOTTRACE_DISK_IO_FAIL_UTIL_PERCENT", 95.0)
    warn_await_ms = env_float("ROOTTRACE_DISK_IO_AWAIT_WARN_MS", 50.0)
    fail_await_ms = env_float("ROOTTRACE_DISK_IO_AWAIT_FAIL_MS", 200.0)
    first = diskstat_snapshot()
    if not first:
        return [
            result(
                "disk_io",
                "Disk I/O pressure",
                "unknown",
                "low",
                "Disk I/O counters were not visible.",
                {},
            )
        ]
    started = time.monotonic()
    time.sleep(max(0.05, min(sample_seconds, 1.0)))
    second = diskstat_snapshot()
    elapsed = max(time.monotonic() - started, 0.05)
    checks: list[dict[str, Any]] = []
    sector_bytes = env_int("ROOTTRACE_DISK_SECTOR_BYTES", 512)
    for name, end in second.items():
        start = first.get(name)
        if not start:
            continue
        read_ops = max(0, end["reads_completed"] - start["reads_completed"])
        write_ops = max(0, end["writes_completed"] - start["writes_completed"])
        read_bytes = max(0, end["sectors_read"] - start["sectors_read"]) * sector_bytes
        write_bytes = max(0, end["sectors_written"] - start["sectors_written"]) * sector_bytes
        read_ms = max(0, end["read_ms"] - start["read_ms"])
        write_ms = max(0, end["write_ms"] - start["write_ms"])
        io_ms = max(0, end["io_ms"] - start["io_ms"])
        weighted_ms = max(0, end["weighted_io_ms"] - start["weighted_io_ms"])
        total_ops = read_ops + write_ops
        avg_await_ms = round((read_ms + write_ms) / total_ops, 2) if total_ops else 0.0
        read_await_ms = round(read_ms / read_ops, 2) if read_ops else 0.0
        write_await_ms = round(write_ms / write_ops, 2) if write_ops else 0.0
        util_percent = round(min(100.0, io_ms / (elapsed * 1000) * 100), 2)
        status, severity = threshold_status(util_percent, warn_util, fail_util)
        status, severity = worse_health(
            (status, severity),
            threshold_status(avg_await_ms, warn_await_ms, fail_await_ms),
        )
        checks.append(
            result(
                "disk_io",
                f"Disk I/O pressure {name}",
                status,
                severity,
                f"Disk I/O utilization on {name} is {util_percent}% with {avg_await_ms} ms average wait.",
                with_thresholds(
                    {
                        "device": name,
                        "sample_seconds": round(elapsed, 2),
                        "read_ops_per_sec": round(read_ops / elapsed, 2),
                        "write_ops_per_sec": round(write_ops / elapsed, 2),
                        "read_bytes_per_sec": round(read_bytes / elapsed, 2),
                        "write_bytes_per_sec": round(write_bytes / elapsed, 2),
                        "read_await_ms": read_await_ms,
                        "write_await_ms": write_await_ms,
                        "avg_await_ms": avg_await_ms,
                        "io_util_percent": util_percent,
                        "weighted_io_ms_delta": weighted_ms,
                        "weighted_io_ms_per_sec": round(weighted_ms / elapsed, 2),
                        "ios_in_progress": end["ios_in_progress"],
                        "await_warn_ms": warn_await_ms,
                        "await_fail_ms": fail_await_ms,
                    },
                    metric="io_util_percent",
                    label="I/O busy",
                    unit="%",
                    warn=warn_util,
                    fail=fail_util,
                ),
            )
        )
    return checks


def check_swap() -> list[dict[str, Any]]:
    swaps = []
    for line in read_text(proc_root() / "swaps").splitlines()[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        device, _, size_kb, used_kb, _ = parts[:5]
        try:
            size = int(size_kb) * 1024
            used = int(used_kb) * 1024
        except ValueError:
            continue
        percent = round((used / size) * 100, 2) if size else 0.0
        status, severity = threshold_status(
            percent,
            env_float("ROOTTRACE_SWAP_WARN_PERCENT", 60.0),
            env_float("ROOTTRACE_SWAP_FAIL_PERCENT", 85.0),
        )
        swaps.append(
            result(
                "swap",
                f"Swap usage {device}",
                status,
                severity,
                f"Swap usage on {device} is {percent}%.",
                with_thresholds(
                    {"device": device, "total_bytes": size, "used_bytes": used, "used_percent": percent},
                    metric="used_percent",
                    label="Swap used",
                    unit="%",
                    warn=env_float("ROOTTRACE_SWAP_WARN_PERCENT", 60.0),
                    fail=env_float("ROOTTRACE_SWAP_FAIL_PERCENT", 85.0),
                ),
            )
        )
    if not swaps and env_bool("ROOTTRACE_REPORT_NO_SWAP", False):
        return [result("swap", "Swap availability", "pass", "low", "No swap devices are configured.", {"swap_devices": 0})]
    return swaps


def meminfo() -> dict[str, int]:
    values: dict[str, int] = {}
    for line in read_text(proc_root() / "meminfo").splitlines():
        if ":" not in line:
            continue
        key, raw = line.split(":", 1)
        parts = raw.strip().split()
        if parts and parts[0].isdigit():
            values[key] = int(parts[0]) * 1024
    return values


def check_memory() -> list[dict[str, Any]]:
    info = meminfo()
    total = info.get("MemTotal", 0)
    available = info.get("MemAvailable", 0)
    if total <= 0:
        return [result("memory", "Memory pressure", "unknown", "low", "Memory information is not available.", {})]
    used_percent = round(((total - available) / total) * 100, 2)
    warn = env_float("ROOTTRACE_MEMORY_WARN_PERCENT", 80.0)
    fail = env_float("ROOTTRACE_MEMORY_FAIL_PERCENT", 90.0)
    status, severity = threshold_status(used_percent, warn, fail)
    return [
        result(
            "memory",
            "Memory pressure",
            status,
            severity,
            f"Memory usage is {used_percent}%.",
            with_thresholds(
                {"total_bytes": total, "available_bytes": available, "used_percent": used_percent},
                metric="used_percent",
                label="Memory used",
                unit="%",
                warn=warn,
                fail=fail,
            ),
        )
    ]


def read_proc_cpu_totals() -> tuple[float, float, float | None] | None:
    """(total, busy, steal) jiffies from /proc/stat's aggregate line.

    Fields are user nice system idle iowait irq softirq steal. guest and
    guest_nice follow but are already counted inside user and nice, so
    including them would double-count. steal is None on kernels that predate
    it, which is different from a kernel reporting zero steal.
    """
    try:
        with open("/proc/stat", "r", encoding="utf-8") as handle:
            line = handle.readline()
    except OSError:
        return None
    parts = line.split()
    if not parts or parts[0] != "cpu":
        return None
    try:
        values = [float(item) for item in parts[1:9]]
    except ValueError:
        return None
    if len(values) < 4:
        return None
    idle = values[3] + (values[4] if len(values) > 4 else 0.0)
    total = sum(values)
    busy = total - idle
    steal = values[7] if len(values) > 7 else None
    return total, busy, steal


def cpu_usage_percent(sample_seconds: float) -> tuple[float, float | None] | None:
    """(busy percent, steal percent) across all cores, or None if unreadable.

    Steal counts toward both total and busy, which is what top reports as %st:
    the vCPU was runnable but the hypervisor scheduled someone else, so the
    time is not idle.
    """
    first = read_proc_cpu_totals()
    if first is None:
        return None
    time.sleep(max(0.05, min(sample_seconds, 1.0)))
    second = read_proc_cpu_totals()
    if second is None:
        return None
    total_delta = second[0] - first[0]
    busy_delta = second[1] - first[1]
    if total_delta <= 0:
        return None
    percent = (busy_delta / total_delta) * 100
    steal_percent = None
    if first[2] is not None and second[2] is not None:
        steal_delta = second[2] - first[2]
        steal_percent = round(max(0.0, min(100.0, (steal_delta / total_delta) * 100)), 2)
    return round(max(0.0, min(100.0, percent)), 2), steal_percent


def check_cpu_usage() -> list[dict[str, Any]]:
    try:
        load1, load5, load15 = os.getloadavg()
    except OSError:
        load1, load5, load15 = 0.0, 0.0, 0.0
    cpus = max(os.cpu_count() or 1, 1)
    load_ratio = round(load1 / cpus, 2)
    sample_seconds = env_float("ROOTTRACE_CPU_SAMPLE_SECONDS", 0.25)
    sample = cpu_usage_percent(sample_seconds)
    steal_percent = None
    if sample is None:
        usage_percent = round(max(0.0, min(100.0, load_ratio * 100)), 2)
        measurement_source = "load_average_fallback"
        message = (
            f"CPU pressure is approximately {usage_percent}% based on 1-minute load "
            f"{load1:.2f} across {cpus} CPU(s)."
        )
    else:
        usage_percent, steal_percent = sample
        measurement_source = "proc_stat_delta"
        message = f"CPU usage is {usage_percent}% across {cpus} CPU(s)."
        if steal_percent:
            message = f"{message} Hypervisor steal is {steal_percent}%."
    warn = env_float("ROOTTRACE_CPU_WARN_PERCENT", 80.0)
    fail = env_float("ROOTTRACE_CPU_FAIL_PERCENT", 95.0)
    status, severity = threshold_status(usage_percent, warn, fail)
    return [
        result(
            "cpu",
            "CPU usage",
            status,
            severity,
            message,
            with_thresholds(
                {
                    "cpu_usage_percent": usage_percent,
                    "cpu_count": cpus,
                    "load_1m": round(load1, 2),
                    "load_5m": round(load5, 2),
                    "load_15m": round(load15, 2),
                    "load_per_cpu": load_ratio,
                    # Omitted rather than zeroed when the kernel does not report
                    # steal: absent means unknown, 0 means measured idle.
                    **({"steal_percent": steal_percent} if steal_percent is not None else {}),
                    "measurement_source": measurement_source,
                    "sample_seconds": sample_seconds,
                    "scale": "0-100 percent across all cores",
                },
                metric="cpu_usage_percent",
                label="CPU used",
                unit="%",
                warn=warn,
                fail=fail,
            ),
        )
    ]


def netdev_snapshot() -> dict[str, dict[str, int]]:
    interfaces: dict[str, dict[str, int]] = {}
    for line in read_text(proc_root() / "net" / "dev").splitlines():
        if ":" not in line:
            continue
        raw_name, raw_values = line.split(":", 1)
        name = raw_name.strip()
        if name == "lo":
            continue
        parts = raw_values.split()
        if len(parts) < 16:
            continue
        try:
            interfaces[name] = {
                "rx_bytes": int(parts[0]),
                "rx_packets": int(parts[1]),
                "rx_errors": int(parts[2]),
                "rx_dropped": int(parts[3]),
                "tx_bytes": int(parts[8]),
                "tx_packets": int(parts[9]),
                "tx_errors": int(parts[10]),
                "tx_dropped": int(parts[11]),
            }
        except ValueError:
            continue
    return interfaces


def sockstat_values() -> dict[str, int]:
    values: dict[str, int] = {}
    for line in read_text(proc_root() / "net" / "sockstat").splitlines():
        parts = line.replace(":", "").split()
        if not parts:
            continue
        namespace = parts[0].lower()
        for index in range(1, len(parts) - 1, 2):
            key = parts[index].lower()
            try:
                values[f"{namespace}_{key}"] = int(parts[index + 1])
            except ValueError:
                continue
    return values


def count_reserved_ports(raw: str, low: int, high: int) -> int:
    total = 0
    for item in split_csv(raw):
        if "-" in item:
            left, right = item.split("-", 1)
            if left.strip().isdigit() and right.strip().isdigit():
                start = max(low, int(left.strip()))
                end = min(high, int(right.strip()))
                if start <= end:
                    total += end - start + 1
        elif item.isdigit():
            port = int(item)
            if low <= port <= high:
                total += 1
    return total


def tcp_port_capacity() -> dict[str, int] | None:
    raw_range = read_text(proc_root() / "sys" / "net" / "ipv4" / "ip_local_port_range").split()
    if len(raw_range) < 2:
        return None
    try:
        low = int(raw_range[0])
        high = int(raw_range[1])
    except ValueError:
        return None
    if high < low:
        return None
    reserved = count_reserved_ports(
        read_text(proc_root() / "sys" / "net" / "ipv4" / "ip_local_reserved_ports"),
        low,
        high,
    )
    total = max(0, high - low + 1)
    return {
        "ephemeral_port_low": low,
        "ephemeral_port_high": high,
        "ephemeral_ports_total": total,
        "ephemeral_ports_reserved": reserved,
        "ephemeral_ports_available": max(0, total - reserved),
    }


def netstat_tcp_values() -> dict[str, int]:
    values: dict[str, int] = {}
    lines = read_text(proc_root() / "net" / "netstat").splitlines()
    for index in range(0, len(lines) - 1, 2):
        header = lines[index].split()
        data = lines[index + 1].split()
        if not header or not data or header[0] != data[0]:
            continue
        namespace = header[0].rstrip(":").lower()
        for key, raw in zip(header[1:], data[1:]):
            try:
                values[f"{namespace}_{key.lower()}"] = int(raw)
            except ValueError:
                continue
    return values


def check_network_health() -> list[dict[str, Any]]:
    sample_seconds = env_float("ROOTTRACE_NETWORK_SAMPLE_SECONDS", 0.25)
    port_warn = env_float("ROOTTRACE_NETWORK_PORT_WARN_PERCENT", 70.0)
    port_fail = env_float("ROOTTRACE_NETWORK_PORT_FAIL_PERCENT", 90.0)
    first = netdev_snapshot()
    if not first:
        return [
            result(
                "network",
                "Network interface health",
                "unknown",
                "low",
                "Network interface counters were not visible.",
                {},
            )
        ]
    first_tcp = netstat_tcp_values()
    started = time.monotonic()
    time.sleep(max(0.05, min(sample_seconds, 1.0)))
    second = netdev_snapshot()
    second_tcp = netstat_tcp_values()
    sockets = sockstat_values()
    elapsed = max(time.monotonic() - started, 0.05)
    checks: list[dict[str, Any]] = []
    port_capacity = tcp_port_capacity()
    if port_capacity:
        tcp_in_use = sockets.get("tcp_inuse", 0)
        tcp_time_wait = sockets.get("tcp_tw", 0)
        used_estimate = max(0, tcp_in_use + tcp_time_wait)
        available = max(port_capacity["ephemeral_ports_available"], 1)
        port_usage_percent = round(min(100.0, used_estimate / available * 100), 2)
        status, severity = threshold_status(port_usage_percent, port_warn, port_fail)
        checks.append(
            result(
                "network",
                "Network TCP socket capacity",
                status,
                severity,
                (
                    f"TCP socket pressure is {port_usage_percent}% of the local ephemeral port range "
                    f"using {used_estimate} estimated active/TIME_WAIT sockets."
                ),
                with_thresholds(
                    {
                        "interface": "tcp sockets",
                        "resource": "tcp sockets",
                        "tcp_in_use": tcp_in_use,
                        "tcp_tw": tcp_time_wait,
                        "tcp_alloc": sockets.get("tcp_alloc"),
                        "tcp_mem": sockets.get("tcp_mem"),
                        "ephemeral_ports_used_estimate": used_estimate,
                        "ephemeral_port_usage_percent": port_usage_percent,
                        **port_capacity,
                    },
                    metric="ephemeral_port_usage_percent",
                    label="Port usage",
                    unit="%",
                    warn=port_warn,
                    fail=port_fail,
                ),
            )
        )
    for name, end in second.items():
        start = first.get(name)
        if not start:
            continue
        rx_error_drop_delta = max(0, end["rx_errors"] - start["rx_errors"]) + max(0, end["rx_dropped"] - start["rx_dropped"])
        tx_error_drop_delta = max(0, end["tx_errors"] - start["tx_errors"]) + max(0, end["tx_dropped"] - start["tx_dropped"])
        error_drop_delta = rx_error_drop_delta + tx_error_drop_delta
        retrans_delta = max(
            0,
            second_tcp.get("tcpext_tcpretranssegs", 0)
            - first_tcp.get("tcpext_tcpretranssegs", 0),
        )
        status = "warn" if error_drop_delta > 0 else "pass"
        severity = "medium" if error_drop_delta > 0 else "low"
        status, severity = worse_health(
            (status, severity),
            threshold_status(retrans_delta, 1, 10),
        )
        checks.append(
            result(
                "network",
                f"Network interface {name}",
                status,
                severity,
                f"Network interface {name} saw {error_drop_delta} dropped/error packet(s) and {retrans_delta} TCP retransmit(s) during the sample.",
                with_thresholds(
                    {
                        "interface": name,
                        "sample_seconds": round(elapsed, 2),
                        "rx_bytes_per_sec": round(max(0, end["rx_bytes"] - start["rx_bytes"]) / elapsed, 2),
                        "tx_bytes_per_sec": round(max(0, end["tx_bytes"] - start["tx_bytes"]) / elapsed, 2),
                        "rx_packets_per_sec": round(max(0, end["rx_packets"] - start["rx_packets"]) / elapsed, 2),
                        "tx_packets_per_sec": round(max(0, end["tx_packets"] - start["tx_packets"]) / elapsed, 2),
                        "rx_error_drop_delta": rx_error_drop_delta,
                        "tx_error_drop_delta": tx_error_drop_delta,
                        "error_drop_delta": error_drop_delta,
                        "tcp_in_use": sockets.get("tcp_inuse"),
                        "tcp_tw": sockets.get("tcp_tw"),
                        "tcp_alloc": sockets.get("tcp_alloc"),
                        "tcp_retrans_segs_delta": retrans_delta,
                    },
                    metric="error_drop_delta",
                    label="Drops/errors",
                    unit="",
                    warn=1,
                    fail=10,
                ),
            )
        )
    return checks


def tcp_check_spec(raw: str) -> tuple[str, str, int] | None:
    parts = raw.split(":")
    if len(parts) == 2:
        name, port = parts
        host = "127.0.0.1"
    elif len(parts) == 3:
        name, host, port = parts
    else:
        return None
    try:
        return name, host, int(port)
    except ValueError:
        return None


def check_tcp_services() -> list[dict[str, Any]]:
    checks = []
    timeout = float(env("ROOTTRACE_TCP_TIMEOUT_SECONDS", "1.5"))
    configured = split_csv(env("ROOTTRACE_CHECK_PORTS"))
    if not configured:
        listeners = listening_tcp_ports()
        if not listeners:
            return [
                result(
                    "tcp",
                    "TCP listener inventory",
                    "unknown",
                    "low",
                    "No configured TCP targets and no local listening sockets were visible.",
                    with_thresholds(
                        {"listener_count": 0, "failed_count": 0},
                        metric="failed_count",
                        label="TCP failures",
                        unit="",
                        warn=1,
                        fail=1,
                    ),
                )
            ]
        return [
            result(
                "tcp",
                "TCP listener inventory",
                "pass",
                "low",
                f"{len(listeners)} local TCP listener(s) were visible.",
                with_thresholds(
                    {"listener_count": len(listeners), "listeners": listeners[:50], "failed_count": 0},
                    metric="failed_count",
                    label="TCP failures",
                    unit="",
                    warn=1,
                    fail=1,
                ),
            )
        ]
    for raw in configured:
        spec = tcp_check_spec(raw)
        if spec is None:
            checks.append(
                result(
                    "tcp",
                    f"TCP service {raw}",
                    "unknown",
                    "low",
                    "TCP check is malformed. Use name:port or name:host:port.",
                    with_thresholds({"spec": raw, "failed_count": 0}, metric="failed_count", label="TCP failures", unit="", warn=1, fail=1),
                )
            )
            continue
        name, host, port = spec
        started = time.monotonic()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                elapsed_ms = round((time.monotonic() - started) * 1000, 2)
                checks.append(
                    result(
                        "tcp",
                        f"{name} TCP reachability",
                        "pass",
                        "low",
                        f"{name} is reachable on {host}:{port}.",
                        with_thresholds(
                            {"host": host, "port": port, "latency_ms": elapsed_ms, "failed_count": 0},
                            metric="failed_count",
                            label="TCP failures",
                            unit="",
                            warn=1,
                            fail=1,
                        ),
                    )
                )
        except OSError as exc:
            checks.append(
                result(
                    "tcp",
                    f"{name} TCP reachability",
                    "fail",
                    "high",
                    f"{name} is not reachable on {host}:{port}.",
                    with_thresholds(
                        {"host": host, "port": port, "error": str(exc), "failed_count": 1},
                        metric="failed_count",
                        label="TCP failures",
                        unit="",
                        warn=1,
                        fail=1,
                    ),
                )
            )
    return checks


def listening_tcp_ports() -> list[dict[str, Any]]:
    listeners: list[dict[str, Any]] = []
    for protocol, path in (("tcp", proc_root() / "net" / "tcp"), ("tcp6", proc_root() / "net" / "tcp6")):
        for line in read_text(path).splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4 or parts[3] != "0A":
                continue
            local = parts[1]
            if ":" not in local:
                continue
            _, raw_port = local.rsplit(":", 1)
            try:
                port = int(raw_port, 16)
            except ValueError:
                continue
            listeners.append({"protocol": protocol, "port": port})
    deduped = {(item["protocol"], item["port"]): item for item in listeners}
    return sorted(deduped.values(), key=lambda item: (item["port"], item["protocol"]))


def process_names() -> set[str]:
    names: set[str] = set()
    root = proc_root()
    if not root.exists():
        return names
    try:
        entries = list(root.iterdir())
    except OSError:
        return names
    for item in entries:
        if not item.name.isdigit():
            continue
        comm = read_text(item / "comm").strip()
        cmdline = read_text(item / "cmdline").replace("\x00", " ").strip()
        if comm:
            names.add(comm)
        if cmdline:
            names.add(cmdline)
    return names


def process_comm_names() -> set[str]:
    names: set[str] = set()
    root = proc_root()
    if not root.exists():
        return names
    try:
        entries = list(root.iterdir())
    except OSError:
        return names
    for item in entries:
        if not item.name.isdigit():
            continue
        comm = read_text(item / "comm").strip()
        if comm:
            names.add(comm)
    return names


def check_processes() -> list[dict[str, Any]]:
    expected = split_csv(env("ROOTTRACE_PROCESS_NAMES"))
    if not expected:
        running = process_comm_names()
        notable = sorted(
            name
            for name in running
            if any(
                candidate in name.lower()
                for candidate in (
                    "apache",
                    "containerd",
                    "dockerd",
                    "elasticsearch",
                    "haproxy",
                    "httpd",
                    "mongod",
                    "mysql",
                    "nginx",
                    "postgres",
                    "rabbitmq",
                    "redis",
                )
            )
        )
        return [
            result(
                "process",
                "Process inventory",
                "pass" if running else "unknown",
                "low",
                f"{len(running)} process name(s) were visible." if running else "Process inventory was not visible.",
                with_thresholds(
                    {"process_count": len(running), "notable_processes": notable[:25], "missing_count": 0},
                    metric="missing_count",
                    label="Missing processes",
                    unit="",
                    warn=1,
                    fail=1,
                ),
            )
        ]
    running = process_names()
    checks = []
    for name in expected:
        matched = any(name in candidate for candidate in running)
        checks.append(
            result(
                "process",
                f"Process {name}",
                "pass" if matched else "fail",
                "low" if matched else "high",
                f"Process {name} {'is running' if matched else 'was not found'}.",
                with_thresholds(
                    {"process": name, "matched": matched, "missing_count": 0 if matched else 1},
                    metric="missing_count",
                    label="Missing processes",
                    unit="",
                    warn=1,
                    fail=1,
                ),
            )
        )
    return checks


def check_systemd_units() -> list[dict[str, Any]]:
    units = split_csv(env("ROOTTRACE_SYSTEMD_UNITS"))
    checks = []
    journal_minutes = max(env_int("ROOTTRACE_SYSTEMD_JOURNAL_WINDOW_MINUTES", 60), 1)
    journal_max_lines = max(env_int("ROOTTRACE_SYSTEMD_JOURNAL_MAX_LINES", 20), 5)
    if not units:
        return check_systemd_failed_units()
    for unit in units:
        unit_state, unit_error = systemd_unit_state(unit)
        if unit_error:
            checks.append(
                result(
                    "systemd",
                    f"systemd unit {unit}",
                    "unknown",
                    "low",
                    f"Could not inspect systemd unit {unit}.",
                    with_thresholds(
                        {"unit": unit, "error": unit_error, "failed_unit_count": 0, "source": "systemd_dbus"},
                        metric="failed_unit_count",
                        label="Failed units",
                        unit="",
                        warn=1,
                        fail=1,
                    ),
                )
            )
            continue
        active_state = unit_state.get("active_state") or "unknown"
        sub_state = unit_state.get("sub_state")
        active = active_state == "active"
        evidence = {
            "unit": unit,
            "active_state": active_state,
            "sub_state": sub_state,
            "failed_unit_count": 0 if active else 1,
            "source": "systemd_dbus",
        }
        message_state = f"{active_state}/{sub_state}" if sub_state else active_state
        message = f"systemd unit {unit} is {message_state}."
        if not active:
            recent_events, journal_error = systemd_journal_unit_error_events(
                unit,
                minutes=journal_minutes,
                max_lines=journal_max_lines,
            )
            evidence.update(
                {
                    "journal_source": "systemd.journal",
                    "journal_window_minutes": journal_minutes,
                    "journal_error_count": len(recent_events),
                    "journal_errors": recent_events[:journal_max_lines],
                    "journal_error": journal_error,
                }
            )
            if recent_events:
                message = f"{message} Recent journal output includes {len(recent_events)} warning/error event(s)."
        checks.append(
            result(
                "systemd",
                f"systemd unit {unit}",
                "pass" if active else "fail",
                "low" if active else "high",
                message,
                with_thresholds(
                    evidence,
                    metric="failed_unit_count",
                    label="Failed units",
                    unit="",
                    warn=1,
                    fail=1,
                ),
            )
        )
    return checks


def _decode_systemd_value(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _systemd_dbus_manager() -> tuple[Any | None, Any | None, str | None]:
    try:
        import dbus  # type: ignore[import-not-found]
    except ImportError:
        return None, None, "python3-dbus is not installed."
    try:
        bus = dbus.SystemBus()
        manager_object = bus.get_object("org.freedesktop.systemd1", "/org/freedesktop/systemd1")
        manager = dbus.Interface(manager_object, "org.freedesktop.systemd1.Manager")
        return bus, manager, None
    except Exception as exc:  # pragma: no cover - depends on host D-Bus/systemd.
        return None, None, str(exc)


def systemd_unit_state(unit: str) -> tuple[dict[str, str], str | None]:
    bus, manager, error = _systemd_dbus_manager()
    if error:
        return {}, error
    try:
        try:
            unit_path = manager.GetUnit(unit)
        except Exception:
            unit_path = manager.LoadUnit(unit)
        unit_object = bus.get_object("org.freedesktop.systemd1", unit_path)
        properties = unit_object.get_dbus_method("Get", "org.freedesktop.DBus.Properties")
        return (
            {
                "active_state": _decode_systemd_value(properties("org.freedesktop.systemd1.Unit", "ActiveState")),
                "sub_state": _decode_systemd_value(properties("org.freedesktop.systemd1.Unit", "SubState")),
                "load_state": _decode_systemd_value(properties("org.freedesktop.systemd1.Unit", "LoadState")),
            },
            None,
        )
    except Exception as exc:  # pragma: no cover - depends on host D-Bus/systemd.
        return {}, str(exc)


def journal_timestamp_utc(value: Any) -> str | None:
    if isinstance(value, datetime):
        timestamp = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return timestamp.astimezone(timezone.utc).isoformat()
    try:
        timestamp_us = int(str(value))
    except (TypeError, ValueError):
        return None
    return datetime.fromtimestamp(timestamp_us / 1_000_000, timezone.utc).isoformat()


def journal_record_text(value: Any, max_length: int = 1000) -> str | None:
    if isinstance(value, bytes):
        text = value.decode("utf-8", "replace").strip()
    elif isinstance(value, datetime):
        text = journal_timestamp_utc(value) or ""
    else:
        text = str(value).strip() if value is not None else ""
    if not text:
        return None
    return text[:max_length]


def journal_event_from_record(record: dict[str, Any]) -> dict[str, Any] | None:
    message = journal_record_text(record.get("MESSAGE"))
    if not message:
        return None
    event = {
        "message": message,
        "priority": journal_record_text(record.get("PRIORITY"), 16),
        "timestamp_utc": journal_timestamp_utc(record.get("__REALTIME_TIMESTAMP")),
        "timestamp_us": journal_record_text(record.get("__REALTIME_TIMESTAMP"), 32),
        "unit": journal_record_text(record.get("_SYSTEMD_UNIT") or record.get("UNIT"), 128),
        "identifier": journal_record_text(record.get("SYSLOG_IDENTIFIER"), 128),
        "pid": journal_record_text(record.get("_PID"), 32),
        "transport": journal_record_text(record.get("_TRANSPORT"), 64),
    }
    return {key: value for key, value in event.items() if value not in (None, "")}


def systemd_journal_events(
    *,
    matches: Iterable[tuple[str, str]],
    max_priority: int,
    minutes: int,
    max_lines: int,
) -> tuple[list[dict[str, Any]], str | None]:
    try:
        from systemd import journal  # type: ignore[import-not-found]
    except ImportError:
        return [], "python3-systemd/systemd-python is not installed."
    try:
        reader = journal.Reader()
        for key, value in matches:
            reader.add_match(f"{key}={value}")
        boot_id = read_first(Path("/proc/sys/kernel/random/boot_id"))
        if boot_id:
            reader.add_match(f"_BOOT_ID={boot_id}")
        reader.seek_realtime(datetime.now(timezone.utc) - timedelta(minutes=minutes))
        events: deque[dict[str, Any]] = deque(maxlen=max_lines)
        for entry in reader:
            record = dict(entry)
            try:
                priority = int(str(record.get("PRIORITY", "7")))
            except (TypeError, ValueError):
                priority = 7
            if priority > max_priority:
                continue
            event = journal_event_from_record(record)
            if event:
                events.append(event)
        return list(events), None
    except Exception as exc:  # pragma: no cover - depends on host journal access.
        return [], str(exc)


def systemd_journal_unit_error_events(unit: str, *, minutes: int, max_lines: int) -> tuple[list[dict[str, Any]], str | None]:
    return systemd_journal_events(matches=(("_SYSTEMD_UNIT", unit),), max_priority=4, minutes=minutes, max_lines=max_lines)


def check_systemd_failed_units() -> list[dict[str, Any]]:
    bus, manager, manager_error = _systemd_dbus_manager()
    if manager_error:
        return [
            result(
                "systemd",
                "systemd failed units",
                "unknown",
                "low",
                "Could not inspect systemd failed units.",
                with_thresholds(
                    {"error": manager_error, "failed_unit_count": 0, "source": "systemd_dbus"},
                    metric="failed_unit_count",
                    label="Failed units",
                    unit="",
                    warn=1,
                    fail=1,
                ),
            )
        ]
    system_state = "not_checked"
    try:
        failed_units = sorted(
            {
                _decode_systemd_value(row[0])
                for row in manager.ListUnits()
                if len(row) > 3 and _decode_systemd_value(row[3]) == "failed"
            }
        )
    except Exception as exc:  # pragma: no cover - depends on host D-Bus/systemd.
        return [
            result(
                "systemd",
                "systemd failed units",
                "unknown",
                "low",
                "Could not inspect systemd failed units.",
                with_thresholds(
                    {"error": str(exc), "failed_unit_count": 0, "source": "systemd_dbus"},
                    metric="failed_unit_count",
                    label="Failed units",
                    unit="",
                    warn=1,
                    fail=1,
                ),
            )
        ]
    if not failed_units:
        return [
            result(
                "systemd",
                "systemd failed units",
                "pass",
                "low",
                "No failed systemd units detected.",
                with_thresholds(
                    {
                        "system_state": system_state,
                        "failed_unit_count": 0,
                        "source": "systemd_dbus",
                    },
                    metric="failed_unit_count",
                    label="Failed units",
                    unit="",
                    warn=1,
                    fail=1,
                ),
            )
        ]
    journal_minutes = max(env_int("ROOTTRACE_SYSTEMD_JOURNAL_WINDOW_MINUTES", 60), 1)
    journal_max_lines = max(env_int("ROOTTRACE_SYSTEMD_JOURNAL_MAX_LINES", 20), 5)
    checks = []
    for unit in failed_units[:50]:
        recent_events: list[dict[str, Any]] = []
        journal_error = None
        recent_events, journal_error = systemd_journal_unit_error_events(
            unit,
            minutes=journal_minutes,
            max_lines=journal_max_lines,
        )
        message = f"systemd unit {unit} is failed."
        if recent_events:
            message = f"{message} Recent journal output includes {len(recent_events)} warning/error event(s)."
        checks.append(
            result(
                "systemd",
                f"systemd unit {unit}",
                "fail",
                "high",
                message,
                with_thresholds(
                    {
                        "system_state": system_state,
                        "unit": unit,
                        "failed_unit_count": 1,
                        "total_failed_unit_count": len(failed_units),
                        "source": "systemd_dbus",
                        "journal_source": "systemd.journal",
                        "journal_window_minutes": journal_minutes,
                        "journal_error_count": len(recent_events),
                        "journal_errors": recent_events[:journal_max_lines],
                        "journal_error": journal_error,
                    },
                    metric="failed_unit_count",
                    label="Failed units",
                    unit="",
                    warn=1,
                    fail=1,
                ),
            )
        )
    return checks


def explicitly_enabled(check_name: str) -> bool:
    return check_name.lower() in {item.lower() for item in split_csv(env("ROOTTRACE_ENABLED_CHECKS"))}


def check_enabled(check_name: str) -> bool:
    name = check_name.lower()
    enabled = {item.lower() for item in split_csv(env("ROOTTRACE_ENABLED_CHECKS"))}
    disabled = {item.lower() for item in split_csv(env("ROOTTRACE_DISABLED_CHECKS"))}
    if name in disabled:
        return False
    return not enabled or name in enabled


def kubernetes_file_checks_enabled() -> bool:
    return any(check_enabled(name) for name in ("kubernetes", "kubernetes_node", "eks"))


def service_check_requested(check_name: str, *target_env_names: str) -> bool:
    env_flag = f"ROOTTRACE_{check_name.upper()}_CHECK"
    return explicitly_enabled(check_name) or env_bool(env_flag, False) or any(env(name) for name in target_env_names)


def process_matches(candidates: Iterable[str]) -> list[str]:
    candidate_list = [candidate.lower() for candidate in candidates]
    running = process_names()
    matches = set()
    for process in running:
        normalized = process.lower()
        for candidate in candidate_list:
            if candidate in normalized:
                matches.add(candidate)
    return sorted(matches)


def basic_auth_headers(username_env: str, password_env: str) -> dict[str, str]:
    username = env(username_env)
    password = env(password_env)
    if username or password:
        return {"Authorization": auth_header(username, password)}
    return {}


def http_status_health(code: int) -> tuple[str, str]:
    if 200 <= code < 400:
        return "pass", "low"
    if code in {401, 403, 404}:
        return "warn", "medium"
    if code >= 500:
        return "fail", "high"
    return "warn", "medium"


def parse_host_port_targets(raw: str, default_port: int, default_name: str) -> list[tuple[str, str, int]]:
    targets: list[tuple[str, str, int]] = []
    for item in split_csv(raw):
        parts = item.split(":")
        try:
            if len(parts) == 1:
                targets.append((default_name, parts[0], default_port))
            elif len(parts) == 2:
                targets.append((parts[0], parts[0], int(parts[1])))
            elif len(parts) == 3:
                targets.append((parts[0], parts[1], int(parts[2])))
        except ValueError:
            targets.append((item, item, default_port))
    return targets


def env_items(*names: str) -> list[str]:
    items: list[str] = []
    for name in names:
        items.extend(split_csv(env(name)))
    return items


def redact_url_credentials(raw: str) -> str:
    if not raw:
        return raw
    try:
        parsed = urlparse(raw)
        if parsed.scheme and parsed.netloc and (parsed.username or parsed.password):
            host = parsed.hostname or ""
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"
            netloc = host
            if parsed.port:
                netloc = f"{netloc}:{parsed.port}"
            return parsed._replace(netloc=netloc).geturl()
    except ValueError:
        pass
    return re.sub(r"(?i)(password|pass|pwd)=\S+", r"\1=[REDACTED]", raw)


def web_service_process_check(
    *,
    check_type: str,
    label: str,
    candidates: Iterable[str],
    requested: bool,
) -> list[dict[str, Any]]:
    matches = process_matches(candidates)
    if not matches and not requested:
        return []
    return [
        result(
            check_type,
            f"{label} process",
            "pass" if matches else "fail",
            "low" if matches else "high",
            f"{label} process {'is running' if matches else 'was not found'}.",
            {"process_matches": matches, "expected_processes": list(candidates)},
        )
    ]


def parse_nginx_stub_status(text: str) -> dict[str, Any]:
    metrics: dict[str, Any] = {}
    active = re.search(r"Active connections:\s*(\d+)", text)
    if active:
        metrics["active_connections"] = int(active.group(1))
    requests = re.search(r"\n\s*(\d+)\s+(\d+)\s+(\d+)\s*\n", text)
    if requests:
        metrics["accepts"] = int(requests.group(1))
        metrics["handled"] = int(requests.group(2))
        metrics["requests"] = int(requests.group(3))
    states = re.search(r"Reading:\s*(\d+)\s+Writing:\s*(\d+)\s+Waiting:\s*(\d+)", text)
    if states:
        metrics["reading"] = int(states.group(1))
        metrics["writing"] = int(states.group(2))
        metrics["waiting"] = int(states.group(3))
    return metrics


def default_nginx_status_urls() -> list[str]:
    configured = env_items("ROOTTRACE_NGINX_DISCOVERY_URLS")
    if configured:
        return configured
    return [
        "http://127.0.0.1/nginx_status",
        "http://127.0.0.1/stub_status",
        "http://localhost/nginx_status",
        "http://localhost/stub_status",
    ]


def existing_default_nginx_log_paths(kind: str) -> list[str]:
    if kind == "access":
        candidates = (
            "/var/log/nginx/access.log",
            "/var/log/nginx/access.log.1",
        )
    else:
        candidates = (
            "/var/log/nginx/error.log",
            "/var/log/nginx/error.log.1",
        )
    return [path for path in candidates if Path(path).exists()]


def tail_file_lines(path: str, max_lines: int) -> tuple[list[str], str | None]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return list(deque(handle, maxlen=max_lines)), None
    except OSError as exc:
        return [], str(exc)


def expand_log_paths(paths: list[str]) -> list[str]:
    expanded: list[str] = []
    seen: set[str] = set()
    for raw_path in paths:
        path_text = raw_path.strip()
        if not path_text:
            continue
        candidates: list[Path]
        if any(marker in path_text for marker in ("*", "?", "[")):
            candidates = sorted(Path().glob(path_text) if not Path(path_text).is_absolute() else Path("/").glob(path_text.lstrip("/")))
        else:
            candidates = [Path(path_text)]
        for candidate in candidates:
            if candidate.suffix in {".gz", ".zip", ".xz", ".bz2"}:
                continue
            resolved = str(candidate)
            if resolved in seen:
                continue
            seen.add(resolved)
            expanded.append(resolved)
    return expanded[:16]


def parse_nginx_access_status_code(line: str) -> int | None:
    stripped = line.strip()
    if not stripped:
        return None
    if stripped.startswith("{") and stripped.endswith("}"):
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            payload = {}
        if isinstance(payload, dict):
            for key in ("status", "status_code", "http_status", "response_status"):
                value = payload.get(key)
                if isinstance(value, int) and 100 <= value <= 599:
                    return value
                if isinstance(value, str) and re.fullmatch(r"\d{3}", value.strip()):
                    return int(value)
    try:
        parts = line.split('"')
        if len(parts) >= 3:
            remainder = parts[2].strip().split()
            if remainder and re.fullmatch(r"\d{3}", remainder[0]):
                return int(remainder[0])
    except Exception:
        pass
    for pattern in (
        r"(?:^|\s)(?:status|status_code|http_status|response_status)[=:]\s*\"?(\d{3})\"?(?:\s|,|$)",
        r"\"(?:status|status_code|http_status|response_status)\"\s*:\s*\"?(\d{3})\"?",
    ):
        match = re.search(pattern, line, flags=re.IGNORECASE)
        if match:
            return int(match.group(1))
    match = re.search(r'"\S+\s+[^"]*"\s+(\d{3})(?:\s|$)', line)
    if match:
        return int(match.group(1))
    tokens = line.split()
    for index, token in enumerate(tokens[:-1]):
        if token.startswith("HTTP/") or token.endswith("HTTP/1.0\"") or token.endswith("HTTP/1.1\"") or token.endswith("HTTP/2.0\""):
            candidate = tokens[index + 1].strip('"')
            if re.fullmatch(r"\d{3}", candidate):
                return int(candidate)
    return None


def parse_nginx_logs(
    *,
    access_paths: list[str],
    error_paths: list[str],
    max_lines: int,
) -> dict[str, Any]:
    status_counts: dict[str, int] = {}
    access_files_read = []
    error_files_read = []
    read_errors = []
    access_log_lines = 0
    unparsed_access_log_lines = 0
    error_log_lines = 0
    error_log_error_count = 0
    error_log_critical_count = 0
    server_error_levels = ("[error]", "[crit]", "[alert]", "[emerg]")
    critical_error_levels = ("[crit]", "[alert]", "[emerg]")

    for path in access_paths:
        lines, error = tail_file_lines(path, max_lines)
        if error:
            read_errors.append({"path": path, "error": error})
            continue
        if not lines:
            continue
        access_files_read.append(path)
        access_log_lines += len(lines)
        for line in lines:
            status_code = parse_nginx_access_status_code(line)
            if status_code is None:
                unparsed_access_log_lines += 1
                continue
            key = str(status_code)
            status_counts[key] = status_counts.get(key, 0) + 1

    for path in error_paths:
        lines, error = tail_file_lines(path, max_lines)
        if error:
            read_errors.append({"path": path, "error": error})
            continue
        if not lines:
            continue
        error_files_read.append(path)
        error_log_lines += len(lines)
        for line in lines:
            lowered = line.lower()
            if any(level in lowered for level in server_error_levels):
                error_log_error_count += 1
            if any(level in lowered for level in critical_error_levels):
                error_log_critical_count += 1

    def status_range_count(start: int, end: int) -> int:
        return sum(
            count
            for raw_code, count in status_counts.items()
            if start <= int(raw_code) <= end
        )

    http_4xx_count = status_range_count(400, 499)
    http_5xx_count = status_range_count(500, 599)
    server_side_error_count = http_5xx_count + error_log_error_count
    status_code_summary = ", ".join(f"{code}: {count}" for code, count in sorted(status_counts.items(), key=lambda item: int(item[0]))[:25])
    read_error_summary = "; ".join(
        f"{item.get('path')}: {item.get('error')}"
        for item in read_errors[:3]
        if isinstance(item, dict)
    )
    return {
        "access_files_read": access_files_read,
        "error_files_read": error_files_read,
        "read_errors": read_errors[:10],
        "read_error_count": len(read_errors),
        "read_error_summary": read_error_summary,
        "access_log_lines": access_log_lines,
        "error_log_lines": error_log_lines,
        "unparsed_access_log_lines": unparsed_access_log_lines,
        "status_counts": dict(sorted(status_counts.items(), key=lambda item: int(item[0]))[-25:]),
        "status_code_summary": status_code_summary,
        "http_2xx_count": status_range_count(200, 299),
        "http_3xx_count": status_range_count(300, 399),
        "http_4xx_count": http_4xx_count,
        "http_404_count": status_counts.get("404", 0),
        "http_5xx_count": http_5xx_count,
        "error_log_error_count": error_log_error_count,
        "error_log_critical_count": error_log_critical_count,
        "server_side_error_count": server_side_error_count,
        "max_lines_per_file": max_lines,
    }


def check_nginx_logs(*, requested: bool, process_found: bool) -> list[dict[str, Any]]:
    access_configured = bool(env("ROOTTRACE_NGINX_ACCESS_LOG_PATH") or env("ROOTTRACE_NGINX_ACCESS_LOG_PATHS"))
    error_configured = bool(env("ROOTTRACE_NGINX_ERROR_LOG_PATH") or env("ROOTTRACE_NGINX_ERROR_LOG_PATHS"))
    access_paths = env_items("ROOTTRACE_NGINX_ACCESS_LOG_PATH", "ROOTTRACE_NGINX_ACCESS_LOG_PATHS")
    error_paths = env_items("ROOTTRACE_NGINX_ERROR_LOG_PATH", "ROOTTRACE_NGINX_ERROR_LOG_PATHS")
    configured_access_paths = list(access_paths)
    configured_error_paths = list(error_paths)
    if not access_paths:
        access_paths = existing_default_nginx_log_paths("access")
    if not error_paths:
        error_paths = existing_default_nginx_log_paths("error")
    access_paths = expand_log_paths(access_paths)
    error_paths = expand_log_paths(error_paths)
    if not access_paths and not error_paths:
        if requested or process_found:
            return [
                result(
                    "nginx",
                    "Nginx HTTP status logs",
                    "unknown",
                    "low",
                    "RootTrace could not find readable Nginx access or error log paths on this host.",
                    {
                        "log_paths_checked": {
                            "access": configured_access_paths or existing_default_nginx_log_paths("access"),
                            "error": configured_error_paths or existing_default_nginx_log_paths("error"),
                        },
                        "hint": "Configure ROOTTRACE_NGINX_ACCESS_LOG_PATHS and ROOTTRACE_NGINX_ERROR_LOG_PATHS if this host writes Nginx logs outside the standard locations.",
                    },
                )
            ]
        return []

    metrics = parse_nginx_logs(
        access_paths=access_paths,
        error_paths=error_paths,
        max_lines=max(env_int("ROOTTRACE_NGINX_LOG_MAX_LINES", 2000), 100),
    )
    has_any_log_data = bool(metrics["access_files_read"] or metrics["error_files_read"])
    if not has_any_log_data and not (requested or access_configured or error_configured or process_found):
        return []
    if not has_any_log_data:
        return [
            result(
                "nginx",
                "Nginx HTTP status logs",
                "unknown",
                "low",
                "Nginx log paths were present or configured, but RootTrace could not read them.",
                {
                    "metrics": metrics,
                    "log_paths_checked": {
                        "access": access_paths,
                        "error": error_paths,
                    },
                },
            )
        ]

    server_errors = int(metrics.get("server_side_error_count") or 0)
    http_5xx = int(metrics.get("http_5xx_count") or 0)
    http_404 = int(metrics.get("http_404_count") or 0)
    http_4xx = int(metrics.get("http_4xx_count") or 0)
    if server_errors > 0 or http_5xx > 0:
        status, severity = "fail", "high"
    elif http_4xx > 0:
        status, severity = "warn", "medium"
    else:
        status, severity = "pass", "low"
    return [
        result(
            "nginx",
            "Nginx HTTP status logs",
            status,
            severity,
            f"Nginx recent logs show {http_5xx} 5xx, {server_errors} server-side error(s), and {http_404} 404 response(s).",
            with_thresholds(
                {
                    "metrics": metrics,
                    "log_paths_checked": {
                        "access": access_paths,
                        "error": error_paths,
                    },
                },
                metric="metrics.server_side_error_count",
                label="Server-side errors",
                unit="",
                warn=1,
                fail=1,
            ),
        )
    ]


def parse_apache_status_auto(text: str) -> dict[str, Any]:
    metrics: dict[str, Any] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, raw_value = line.split(":", 1)
        normalized = key.strip().lower().replace(" ", "_")
        value = raw_value.strip()
        if not value:
            continue
        try:
            metrics[normalized] = int(value)
        except ValueError:
            try:
                metrics[normalized] = float(value)
            except ValueError:
                metrics[normalized] = value[:200]
    return metrics


def parse_haproxy_stats_csv(text: str) -> dict[str, Any]:
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return {}
    if lines[0].startswith("# "):
        lines[0] = lines[0][2:]
    elif lines[0].startswith("#"):
        lines[0] = lines[0][1:]
    if "pxname" not in lines[0] or "svname" not in lines[0]:
        return {}
    rows = list(csv.DictReader(lines))
    down = []
    maintenance = []
    current_sessions = 0
    for row in rows:
        svname = (row.get("svname") or "").upper()
        status = (row.get("status") or "").upper()
        if svname == "FRONTEND":
            try:
                current_sessions += int(row.get("scur") or 0)
            except ValueError:
                pass
            continue
        if svname == "BACKEND" or row.get("type") in {"1", "2"}:
            backend = {"proxy": row.get("pxname"), "server": row.get("svname"), "status": status}
            if status.startswith("DOWN") or status in {"NOLB", "STOPPED"}:
                down.append(backend)
            elif "MAINT" in status:
                maintenance.append(backend)
    return {
        "row_count": len(rows),
        "current_sessions": current_sessions,
        "down_backends": down[:25],
        "maintenance_backends": maintenance[:25],
        "down_count": len(down),
        "maintenance_count": len(maintenance),
    }


def check_http_status_urls(
    *,
    check_type: str,
    label: str,
    urls: list[str],
    headers: dict[str, str],
    parser: Callable[[str], dict[str, Any]] | None = None,
    require_metrics: bool = False,
    suppress_failures: bool = False,
    stop_after_first_metrics: bool = False,
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for raw_url in urls:
        safe_url = redact_url_credentials(raw_url)
        try:
            started = time.monotonic()
            code, text = http_text_status(raw_url, headers=headers)
            elapsed_ms = round((time.monotonic() - started) * 1000, 2)
            status, severity = http_status_health(code)
            metrics = parser(text) if parser and 200 <= code < 400 else {}
            missing_required_metrics = require_metrics and 200 <= code < 400 and not metrics
            if missing_required_metrics:
                status, severity = "unknown", "low"
            if check_type == "haproxy" and metrics.get("down_count"):
                status, severity = "fail", "critical"
            elif check_type == "haproxy" and metrics.get("maintenance_count") and status == "pass":
                status, severity = "warn", "medium"
            evidence = {
                "url": safe_url,
                "http_status": code,
                "latency_ms": elapsed_ms,
                "metrics": metrics,
            }
            if check_type == "nginx":
                evidence["metrics"] = {**metrics, "latency_ms": elapsed_ms}
            if missing_required_metrics:
                evidence["metrics_parse_status"] = "missing_expected_metrics"
            if check_type == "haproxy":
                evidence = with_thresholds(
                    evidence,
                    metric="metrics.down_count",
                    label="Down backends",
                    unit="",
                    warn=1,
                    fail=1,
                )
            if suppress_failures and (code < 200 or code >= 400 or missing_required_metrics):
                continue
            checks.append(
                result(
                    check_type,
                    f"{label} status endpoint",
                    status,
                    severity,
                    (
                        f"{label} status endpoint returned HTTP {code} but did not expose expected status metrics."
                        if missing_required_metrics
                        else f"{label} status endpoint returned HTTP {code}."
                    ),
                    evidence,
                )
            )
            if stop_after_first_metrics and metrics:
                break
        except Exception as exc:
            if suppress_failures:
                continue
            checks.append(
                result(
                    check_type,
                    f"{label} status endpoint",
                    "fail",
                    "high",
                    f"{label} status endpoint check failed for {safe_url}.",
                    {"url": safe_url, "error": str(exc)},
                )
            )
    return checks


def parse_http_target(raw: str) -> tuple[str, str]:
    def normalize_url(value: str) -> str:
        value = value.strip()
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
            return value
        return f"http://{value}"

    if "=" in raw:
        name, url = raw.split("=", 1)
        normalized = normalize_url(url)
        parsed = urlparse(normalized)
        return name.strip() or parsed.netloc or normalized, normalized
    normalized = normalize_url(raw)
    parsed = urlparse(normalized)
    return parsed.netloc or raw.strip(), normalized


def parse_http_status_ranges(raw: str) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for item in split_csv(raw):
        if "-" in item:
            left, right = item.split("-", 1)
            if left.strip().isdigit() and right.strip().isdigit():
                start = int(left.strip())
                end = int(right.strip())
                ranges.append((min(start, end), max(start, end)))
        elif item.isdigit():
            code = int(item)
            ranges.append((code, code))
    return ranges


def http_status_matches(code: int, ranges: list[tuple[int, int]]) -> bool:
    if not ranges:
        return 200 <= code < 400
    return any(start <= code <= end for start, end in ranges)


def check_http_endpoints() -> list[dict[str, Any]]:
    targets = env_items("ROOTTRACE_HTTP_TARGET", "ROOTTRACE_HTTP_TARGETS", "ROOTTRACE_HEALTH_URLS")
    if not targets:
        return []
    checks: list[dict[str, Any]] = []
    expected_raw = env("ROOTTRACE_HTTP_EXPECTED_STATUS")
    expected_ranges = parse_http_status_ranges(expected_raw)
    timeout = env_float("ROOTTRACE_HTTP_CHECK_TIMEOUT_SECONDS", CHECK_TIMEOUT_SECONDS)
    body_match = env("ROOTTRACE_HTTP_EXPECTED_BODY")
    for raw in targets:
        name, url = parse_http_target(raw)
        safe_url = redact_url_credentials(url)
        try:
            started = time.monotonic()
            code, text = http_text_status(url, timeout=timeout)
            elapsed_ms = round((time.monotonic() - started) * 1000, 2)
            status_ok = http_status_matches(code, expected_ranges)
            body_ok = body_match in text if body_match else True
            status = "pass" if status_ok and body_ok else "fail" if code >= 500 or not body_ok else "warn"
            severity = "low" if status == "pass" else "high" if status == "fail" else "medium"
            checks.append(
                result(
                    "http",
                    f"{name} HTTP endpoint",
                    status,
                    severity,
                    f"{name} returned HTTP {code} in {elapsed_ms} ms.",
                    with_thresholds(
                        {
                            "target": name,
                            "url": safe_url,
                            "http_status": code,
                            "latency_ms": elapsed_ms,
                            "expected_statuses": expected_raw or "200-399",
                            "expected_body_configured": bool(body_match),
                            "expected_body_matched": body_ok,
                        },
                        metric="latency_ms",
                        label="HTTP latency",
                        unit="ms",
                        warn=env_float("ROOTTRACE_HTTP_LATENCY_WARN_MS", 500.0),
                        fail=env_float("ROOTTRACE_HTTP_LATENCY_FAIL_MS", 1500.0),
                    ),
                )
            )
        except Exception as exc:
            checks.append(
                result(
                    "http",
                    f"{name} HTTP endpoint",
                    "fail",
                    "high",
                    f"{name} HTTP endpoint check failed.",
                    {"target": name, "url": safe_url, "error": str(exc)},
                )
            )
    return checks


def tls_targets_from_config() -> list[tuple[str, str, int]]:
    targets: list[tuple[str, str, int]] = []
    for raw in env_items("ROOTTRACE_TLS_TARGET", "ROOTTRACE_TLS_TARGETS"):
        item = raw.strip()
        if not item:
            continue
        parsed = urlparse(item if "://" in item else f"tls://{item}")
        host = parsed.hostname
        if host:
            targets.append((parsed.netloc or host, host, parsed.port or 443))
    if env_bool("ROOTTRACE_TLS_FROM_HTTP_TARGETS", True):
        for raw in env_items("ROOTTRACE_HTTP_TARGET", "ROOTTRACE_HTTP_TARGETS", "ROOTTRACE_HEALTH_URLS"):
            _, url = parse_http_target(raw)
            parsed = urlparse(url)
            if parsed.scheme == "https" and parsed.hostname:
                targets.append((parsed.netloc or parsed.hostname, parsed.hostname, parsed.port or 443))
    deduped = {(host, port): (name, host, port) for name, host, port in targets}
    return list(deduped.values())


def check_tls_certificates() -> list[dict[str, Any]]:
    targets = tls_targets_from_config()
    if not targets:
        return []
    checks: list[dict[str, Any]] = []
    warn_days = env_int("ROOTTRACE_TLS_WARN_DAYS", 30)
    fail_days = env_int("ROOTTRACE_TLS_FAIL_DAYS", 7)
    timeout = env_float("ROOTTRACE_TLS_TIMEOUT_SECONDS", CHECK_TIMEOUT_SECONDS)
    for name, host, port in targets:
        try:
            context = ssl.create_default_context()
            started = time.monotonic()
            with socket.create_connection((host, port), timeout=timeout) as raw_sock:
                with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                    cert = tls_sock.getpeercert()
            elapsed_ms = round((time.monotonic() - started) * 1000, 2)
            not_after = cert.get("notAfter") if isinstance(cert, dict) else None
            expires_at = ssl.cert_time_to_seconds(not_after) if not_after else 0
            days_remaining = round((expires_at - time.time()) / 86400, 2) if expires_at else None
            if days_remaining is None:
                status, severity = "unknown", "medium"
            elif days_remaining <= fail_days:
                status, severity = "fail", "critical"
            elif days_remaining <= warn_days:
                status, severity = "warn", "medium"
            else:
                status, severity = "pass", "low"
            checks.append(
                result(
                    "tls",
                    f"{name} TLS certificate",
                    status,
                    severity,
                    f"{name} TLS certificate expires in {days_remaining if days_remaining is not None else 'unknown'} day(s).",
                    with_thresholds(
                        {
                            "target": name,
                            "host": host,
                            "port": port,
                            "latency_ms": elapsed_ms,
                            "issuer": cert.get("issuer") if isinstance(cert, dict) else None,
                            "subject": cert.get("subject") if isinstance(cert, dict) else None,
                            "not_after": not_after,
                            "days_remaining": days_remaining,
                        },
                        metric="days_remaining",
                        label="Days remaining",
                        unit="d",
                        warn=warn_days,
                        fail=fail_days,
                        higher_is_worse=False,
                    ),
                )
            )
        except Exception as exc:
            checks.append(
                result(
                    "tls",
                    f"{name} TLS certificate",
                    "fail",
                    "high",
                    f"TLS certificate check failed for {host}:{port}.",
                    {"target": name, "host": host, "port": port, "error": str(exc)},
                )
            )
    return checks


def check_kernel_events() -> list[dict[str, Any]]:
    if not env_bool("ROOTTRACE_KERNEL_EVENT_CHECK", True):
        return []
    minutes = max(env_int("ROOTTRACE_KERNEL_EVENT_WINDOW_MINUTES", 15), 1)
    max_lines = max(env_int("ROOTTRACE_KERNEL_EVENT_MAX_LINES", 50), 10)
    events, journal_error = systemd_journal_events(
        matches=(("_TRANSPORT", "kernel"),),
        max_priority=3,
        minutes=minutes,
        max_lines=max_lines,
    )
    if journal_error and not events:
        return [
            result(
                "kernel",
                "Kernel event health",
                "unknown",
                "low",
                "Could not inspect recent kernel events.",
                {"event_count": 0, "error": journal_error, "source": "systemd.journal"},
            )
        ]
    oom_events = [
        event
        for event in events
        if re.search(
            r"\b(out of memory|oom-kill|killed process)\b",
            event.get("message", ""),
            re.IGNORECASE,
        )
    ]
    io_events = [
        event
        for event in events
        if re.search(
            r"\b(i/o error|blk_update_request|nvme|filesystem error)\b",
            event.get("message", ""),
            re.IGNORECASE,
        )
    ]
    event_count = len(events)
    status = "fail" if oom_events else "warn" if event_count else "pass"
    severity = "high" if oom_events else "medium" if event_count else "low"
    return [
        result(
            "kernel",
            "Kernel event health",
            status,
            severity,
            f"Recent kernel event scan found {event_count} error event(s), including {len(oom_events)} OOM signal(s).",
            with_thresholds(
                {
                    "event_count": event_count,
                    "oom_event_count": len(oom_events),
                    "io_error_count": len(io_events),
                    "window_minutes": minutes,
                    "source": "systemd.journal",
                    "journal_error": journal_error,
                    "events": events[:max_lines],
                },
                metric="event_count",
                label="Kernel errors",
                unit="",
                warn=1,
                fail=1,
            ),
        )
    ]


def check_nginx() -> list[dict[str, Any]]:
    urls = env_items("ROOTTRACE_NGINX_STATUS_URL", "ROOTTRACE_NGINX_STATUS_URLS")
    requested = service_check_requested("nginx", "ROOTTRACE_NGINX_STATUS_URL", "ROOTTRACE_NGINX_STATUS_URLS")
    matches = process_matches(("nginx",))
    checks = web_service_process_check(
        check_type="nginx",
        label="Nginx",
        candidates=("nginx",),
        requested=requested,
    )
    auto_discovered = False
    if not urls and matches and env_bool("ROOTTRACE_NGINX_AUTO_DISCOVER_STATUS", True):
        urls = default_nginx_status_urls()
        auto_discovered = True
    checks.extend(
        check_http_status_urls(
            check_type="nginx",
            label="Nginx",
            urls=urls,
            headers=basic_auth_headers("ROOTTRACE_NGINX_USERNAME", "ROOTTRACE_NGINX_PASSWORD"),
            parser=parse_nginx_stub_status,
            require_metrics=True,
            suppress_failures=auto_discovered,
            stop_after_first_metrics=auto_discovered,
        )
    )
    checks.extend(check_nginx_logs(requested=requested, process_found=bool(matches)))
    return checks


def check_apache() -> list[dict[str, Any]]:
    urls = env_items("ROOTTRACE_APACHE_STATUS_URL", "ROOTTRACE_APACHE_STATUS_URLS")
    requested = service_check_requested("apache", "ROOTTRACE_APACHE_STATUS_URL", "ROOTTRACE_APACHE_STATUS_URLS")
    checks = web_service_process_check(
        check_type="apache",
        label="Apache HTTP Server",
        candidates=("apache2", "httpd"),
        requested=requested,
    )
    checks.extend(
        check_http_status_urls(
            check_type="apache",
            label="Apache HTTP Server",
            urls=urls,
            headers=basic_auth_headers("ROOTTRACE_APACHE_USERNAME", "ROOTTRACE_APACHE_PASSWORD"),
            parser=parse_apache_status_auto,
        )
    )
    return checks


def check_haproxy() -> list[dict[str, Any]]:
    urls = env_items("ROOTTRACE_HAPROXY_STATS_URL", "ROOTTRACE_HAPROXY_STATS_URLS")
    requested = service_check_requested("haproxy", "ROOTTRACE_HAPROXY_STATS_URL", "ROOTTRACE_HAPROXY_STATS_URLS")
    checks = web_service_process_check(
        check_type="haproxy",
        label="HAProxy",
        candidates=("haproxy",),
        requested=requested,
    )
    checks.extend(
        check_http_status_urls(
            check_type="haproxy",
            label="HAProxy",
            urls=urls,
            headers=basic_auth_headers("ROOTTRACE_HAPROXY_USERNAME", "ROOTTRACE_HAPROXY_PASSWORD"),
            parser=parse_haproxy_stats_csv,
        )
    )
    return checks


def parse_database_host_target(
    item: str,
    *,
    default_port: int,
    default_name: str,
    default_database: str,
) -> dict[str, Any]:
    parts = item.split(":")
    name = default_name
    host = item
    port = default_port
    database = default_database
    try:
        if len(parts) == 2:
            host = parts[0]
            port = int(parts[1])
        elif len(parts) == 3:
            name = parts[0]
            host = parts[1]
            port = int(parts[2])
        elif len(parts) >= 4:
            name = parts[0]
            host = parts[1]
            port = int(parts[2])
            database = parts[3]
    except ValueError:
        host = item
        port = default_port
    return {
        "name": name or default_name,
        "host": host,
        "port": port,
        "database": database,
        "safe_target": f"{name or default_name}:{host}:{port}/{database}",
    }


def parse_database_url_target(item: str, *, default_name: str, default_port: int) -> dict[str, Any]:
    parsed = urlparse(item)
    name = parsed.hostname or default_name
    return {
        "name": name,
        "host": parsed.hostname,
        "port": parsed.port or default_port,
        "database": parsed.path.lstrip("/") or None,
        "username": unquote(parsed.username) if parsed.username else None,
        "password": unquote(parsed.password) if parsed.password else None,
        "safe_target": redact_url_credentials(item),
        "url": item,
    }


def postgres_targets() -> list[dict[str, Any]]:
    items = env_items(
        "ROOTTRACE_POSTGRES_DSN",
        "ROOTTRACE_POSTGRES_DSNS",
        "ROOTTRACE_POSTGRES_URL",
        "ROOTTRACE_POSTGRES_URLS",
        "ROOTTRACE_POSTGRES_TARGETS",
        "ROOTTRACE_POSTGRESQL_DSN",
        "ROOTTRACE_POSTGRESQL_DSNS",
        "ROOTTRACE_POSTGRESQL_URL",
        "ROOTTRACE_POSTGRESQL_URLS",
        "ROOTTRACE_POSTGRESQL_TARGETS",
    )
    targets: list[dict[str, Any]] = []
    default_database = env("ROOTTRACE_POSTGRES_DATABASE", "postgres")
    username = env("ROOTTRACE_POSTGRES_USERNAME") or env("ROOTTRACE_POSTGRES_USER")
    password = env("ROOTTRACE_POSTGRES_PASSWORD")
    for item in items:
        if item.startswith(("postgres://", "postgresql://")) or "=" in item:
            safe_target = redact_url_credentials(item)
            parsed = urlparse(item)
            targets.append(
                {
                    "name": parsed.hostname or "postgres",
                    "dsn": item,
                    "safe_target": safe_target,
                }
            )
            continue
        target = parse_database_host_target(
            item,
            default_port=5432,
            default_name="postgres",
            default_database=default_database,
        )
        target["kwargs"] = {
            "host": target["host"],
            "port": target["port"],
            "dbname": target["database"],
        }
        if username:
            target["kwargs"]["user"] = username
        if password:
            target["kwargs"]["password"] = password
        targets.append(target)
    return targets


def check_postgres() -> list[dict[str, Any]]:
    targets = postgres_targets()
    if not targets:
        return []
    try:
        import psycopg  # type: ignore

        driver = "psycopg"
    except Exception:
        try:
            import psycopg2 as psycopg  # type: ignore

            driver = "psycopg2"
        except Exception:
            return [
                result(
                    "postgres",
                    "PostgreSQL dependency",
                    "unknown",
                    "medium",
                    "Install psycopg in the collector image or host environment to enable read-only PostgreSQL health checks.",
                    {"target": target["safe_target"], "dependency": "psycopg"},
                )
                for target in targets
            ]

    checks: list[dict[str, Any]] = []
    timeout = env_int("ROOTTRACE_POSTGRES_TIMEOUT_SECONDS", int(CHECK_TIMEOUT_SECONDS))
    warn_percent = env_float("ROOTTRACE_POSTGRES_CONNECTION_WARN_PERCENT", 80.0)
    fail_percent = env_float("ROOTTRACE_POSTGRES_CONNECTION_FAIL_PERCENT", 90.0)
    lag_fail_seconds = env_int("ROOTTRACE_POSTGRES_REPLICA_LAG_FAIL_SECONDS", 30)
    for target in targets:
        conn = None
        try:
            started = time.monotonic()
            if target.get("dsn"):
                conn = psycopg.connect(target["dsn"], connect_timeout=timeout, application_name="roottrace_collector")
            else:
                conn = psycopg.connect(**target["kwargs"], connect_timeout=timeout, application_name="roottrace_collector")
            if hasattr(conn, "autocommit"):
                conn.autocommit = True
            with conn.cursor() as cursor:
                cursor.execute("SELECT 1")
                cursor.fetchone()
                cursor.execute("SELECT count(*) FROM pg_stat_activity")
                active_connections = int(cursor.fetchone()[0] or 0)
                cursor.execute("SHOW max_connections")
                max_connections = int(cursor.fetchone()[0] or 0)
                cursor.execute("SELECT pg_is_in_recovery()")
                in_recovery = bool(cursor.fetchone()[0])
                cursor.execute("SELECT version()")
                version = str(cursor.fetchone()[0] or "").split(" on ", 1)[0]
                long_query_seconds = env_int("ROOTTRACE_POSTGRES_LONG_QUERY_SECONDS", 60)
                deadlocks = blocked_sessions = long_running_queries = idle_in_transaction = None
                cache_hit_percent = database_size_bytes = transaction_id_age = None
                replication_slot_lag_bytes = None
                try:
                    cursor.execute("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock'")
                    blocked_sessions = int(cursor.fetchone()[0] or 0)
                except Exception:
                    pass
                try:
                    cursor.execute("SELECT count(*) FROM pg_stat_activity WHERE state = 'active' AND now() - query_start > (%s || ' seconds')::interval", (long_query_seconds,))
                    long_running_queries = int(cursor.fetchone()[0] or 0)
                except Exception:
                    pass
                try:
                    cursor.execute("SELECT count(*) FROM pg_stat_activity WHERE state = 'idle in transaction'")
                    idle_in_transaction = int(cursor.fetchone()[0] or 0)
                except Exception:
                    pass
                try:
                    cursor.execute("SELECT COALESCE(sum(deadlocks), 0) FROM pg_stat_database")
                    deadlocks = int(cursor.fetchone()[0] or 0)
                except Exception:
                    pass
                try:
                    cursor.execute("SELECT round((sum(blks_hit)::numeric / NULLIF(sum(blks_hit + blks_read), 0)) * 100, 2) FROM pg_stat_database")
                    raw_cache = cursor.fetchone()[0]
                    cache_hit_percent = float(raw_cache) if raw_cache is not None else None
                except Exception:
                    pass
                try:
                    cursor.execute("SELECT pg_database_size(current_database())")
                    database_size_bytes = int(cursor.fetchone()[0] or 0)
                except Exception:
                    pass
                try:
                    cursor.execute("SELECT age(datfrozenxid) FROM pg_database WHERE datname = current_database()")
                    transaction_id_age = int(cursor.fetchone()[0] or 0)
                except Exception:
                    pass
                try:
                    cursor.execute("SELECT max(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)) FROM pg_replication_slots WHERE restart_lsn IS NOT NULL")
                    raw_slot_lag = cursor.fetchone()[0]
                    replication_slot_lag_bytes = int(raw_slot_lag) if raw_slot_lag is not None else None
                except Exception:
                    pass
                replica_lag_seconds = None
                if in_recovery:
                    cursor.execute("SELECT EXTRACT(EPOCH FROM now() - pg_last_xact_replay_timestamp())")
                    raw_lag = cursor.fetchone()[0]
                    replica_lag_seconds = round(float(raw_lag), 2) if raw_lag is not None else None
            elapsed_ms = round((time.monotonic() - started) * 1000, 2)
            connection_percent = round((active_connections / max_connections) * 100, 2) if max_connections else None
            status, severity = ("pass", "low")
            if connection_percent is not None:
                status, severity = threshold_status(connection_percent, warn_percent, fail_percent)
            if replica_lag_seconds is not None and replica_lag_seconds >= lag_fail_seconds:
                status, severity = "fail", "critical"
            elif any((blocked_sessions, long_running_queries, idle_in_transaction)) and status == "pass":
                status, severity = "warn", "medium"
            checks.append(
                result(
                    "postgres",
                    f"{target['name']} PostgreSQL health",
                    status,
                    severity,
                    f"PostgreSQL responded in {elapsed_ms} ms; recovery mode is {in_recovery}.",
                    with_thresholds(
                        {
                        "target": target["safe_target"],
                        "driver": driver,
                        "latency_ms": elapsed_ms,
                        "version": version,
                        "active_connections": active_connections,
                        "max_connections": max_connections,
                        "connection_percent": connection_percent,
                        "in_recovery": in_recovery,
                        "replica_lag_seconds": replica_lag_seconds,
                        "blocked_sessions": blocked_sessions,
                        "long_running_queries": long_running_queries,
                        "long_query_seconds": long_query_seconds,
                        "idle_in_transaction_count": idle_in_transaction,
                        "deadlocks": deadlocks,
                        "cache_hit_percent": cache_hit_percent,
                        "database_size_bytes": database_size_bytes,
                        "transaction_id_age": transaction_id_age,
                        "replication_slot_lag_bytes": replication_slot_lag_bytes,
                        },
                        metric="connection_percent",
                        label="DB connections",
                        unit="%",
                        warn=warn_percent,
                        fail=fail_percent,
                    ),
                )
            )
        except Exception as exc:
            checks.append(
                result(
                    "postgres",
                    f"{target['name']} PostgreSQL health",
                    "fail",
                    "high",
                    f"PostgreSQL check failed for {target['safe_target']}.",
                    {"target": target["safe_target"], "error": str(exc)},
                )
            )
        finally:
            if conn is not None:
                conn.close()
    return checks


def mysql_targets() -> list[dict[str, Any]]:
    items = env_items(
        "ROOTTRACE_MYSQL_DSN",
        "ROOTTRACE_MYSQL_DSNS",
        "ROOTTRACE_MYSQL_URL",
        "ROOTTRACE_MYSQL_URLS",
        "ROOTTRACE_MYSQL_TARGETS",
        "ROOTTRACE_MARIADB_DSN",
        "ROOTTRACE_MARIADB_DSNS",
        "ROOTTRACE_MARIADB_URL",
        "ROOTTRACE_MARIADB_URLS",
        "ROOTTRACE_MARIADB_TARGETS",
    )
    targets: list[dict[str, Any]] = []
    default_database = env("ROOTTRACE_MYSQL_DATABASE")
    username = env("ROOTTRACE_MYSQL_USERNAME") or env("ROOTTRACE_MYSQL_USER")
    password = env("ROOTTRACE_MYSQL_PASSWORD")
    for item in items:
        if item.startswith(("mysql://", "mariadb://")):
            parsed = parse_database_url_target(item, default_name="mysql", default_port=3306)
            kwargs = {
                "host": parsed["host"] or "localhost",
                "port": parsed["port"],
                "database": parsed["database"] or None,
                "user": parsed["username"],
                "password": parsed["password"],
            }
        else:
            parsed = parse_database_host_target(
                item,
                default_port=3306,
                default_name="mysql",
                default_database=default_database,
            )
            kwargs = {
                "host": parsed["host"],
                "port": parsed["port"],
                "database": parsed["database"] or None,
                "user": username or None,
                "password": password or None,
            }
        parsed["kwargs"] = {key: value for key, value in kwargs.items() if value not in {None, ""}}
        targets.append(parsed)
    return targets


def mysql_fetch_status(cursor, name: str) -> str | None:
    cursor.execute("SHOW GLOBAL STATUS LIKE %s", (name,))
    row = cursor.fetchone()
    return str(row.get("Value")) if row else None


def mysql_fetch_variable(cursor, name: str) -> str | None:
    cursor.execute("SHOW VARIABLES LIKE %s", (name,))
    row = cursor.fetchone()
    return str(row.get("Value")) if row else None


def check_mysql() -> list[dict[str, Any]]:
    targets = mysql_targets()
    if not targets:
        return []
    try:
        import mysql.connector  # type: ignore
        from mysql.connector import Error as MySQLError  # type: ignore
    except Exception:
        return [
            result(
                "mysql",
                "MySQL dependency",
                "unknown",
                "medium",
                "Install mysql-connector-python in the collector image or host environment to enable read-only MySQL/MariaDB checks.",
                {"target": target["safe_target"], "dependency": "mysql-connector-python"},
            )
            for target in targets
        ]

    checks: list[dict[str, Any]] = []
    timeout = env_int("ROOTTRACE_MYSQL_TIMEOUT_SECONDS", int(CHECK_TIMEOUT_SECONDS))
    warn_percent = env_float("ROOTTRACE_MYSQL_CONNECTION_WARN_PERCENT", 80.0)
    fail_percent = env_float("ROOTTRACE_MYSQL_CONNECTION_FAIL_PERCENT", 90.0)
    lag_fail_seconds = env_int("ROOTTRACE_MYSQL_REPLICA_LAG_FAIL_SECONDS", 30)
    for target in targets:
        conn = None
        cursor = None
        try:
            started = time.monotonic()
            conn = mysql.connector.connect(**target["kwargs"], connection_timeout=timeout)
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT 1 AS ok")
            cursor.fetchone()
            cursor.execute("SELECT VERSION() AS version")
            version_row = cursor.fetchone() or {}
            active_connections = int(mysql_fetch_status(cursor, "Threads_connected") or 0)
            threads_running = int(mysql_fetch_status(cursor, "Threads_running") or 0)
            aborted_connects = int(mysql_fetch_status(cursor, "Aborted_connects") or 0)
            slow_queries = int(mysql_fetch_status(cursor, "Slow_queries") or 0)
            rejected_connections = int(mysql_fetch_status(cursor, "Connection_errors_max_connections") or 0)
            innodb_row_lock_waits = int(mysql_fetch_status(cursor, "Innodb_row_lock_waits") or 0)
            innodb_row_lock_time_ms = int(mysql_fetch_status(cursor, "Innodb_row_lock_time") or 0)
            max_used_connections = int(mysql_fetch_status(cursor, "Max_used_connections") or 0)
            max_connections = int(mysql_fetch_variable(cursor, "max_connections") or 0)
            read_only = mysql_fetch_variable(cursor, "read_only")
            replica_lag_seconds = None
            replica_status_error = None
            try:
                cursor.execute("SHOW REPLICA STATUS")
                replica = cursor.fetchone()
            except MySQLError as exc:
                replica_status_error = str(exc)
                try:
                    cursor.execute("SHOW SLAVE STATUS")
                    replica = cursor.fetchone()
                    replica_status_error = None
                except MySQLError as fallback_exc:
                    replica = None
                    replica_status_error = str(fallback_exc)
            if replica:
                raw_lag = replica.get("Seconds_Behind_Source", replica.get("Seconds_Behind_Master"))
                replica_lag_seconds = int(raw_lag) if raw_lag is not None else None
            elapsed_ms = round((time.monotonic() - started) * 1000, 2)
            connection_percent = round((active_connections / max_connections) * 100, 2) if max_connections else None
            status, severity = ("pass", "low")
            if connection_percent is not None:
                status, severity = threshold_status(connection_percent, warn_percent, fail_percent)
            if replica_lag_seconds is not None and replica_lag_seconds >= lag_fail_seconds:
                status, severity = "fail", "critical"
            elif any((aborted_connects, slow_queries, rejected_connections, innodb_row_lock_waits)) and status == "pass":
                status, severity = "warn", "medium"
            checks.append(
                result(
                    "mysql",
                    f"{target['name']} MySQL/MariaDB health",
                    status,
                    severity,
                    f"MySQL/MariaDB responded in {elapsed_ms} ms.",
                    with_thresholds(
                        {
                        "target": target["safe_target"],
                        "latency_ms": elapsed_ms,
                        "version": version_row.get("version"),
                        "active_connections": active_connections,
                        "threads_running": threads_running,
                        "max_connections": max_connections,
                        "max_used_connections": max_used_connections,
                        "connection_percent": connection_percent,
                        "read_only": read_only,
                        "replica_lag_seconds": replica_lag_seconds,
                        "replica_status_available": replica is not None,
                        "replica_status_error": replica_status_error,
                        "replica_io_running": replica.get("Replica_IO_Running", replica.get("Slave_IO_Running")) if replica else None,
                        "replica_sql_running": replica.get("Replica_SQL_Running", replica.get("Slave_SQL_Running")) if replica else None,
                        "aborted_connects": aborted_connects,
                        "slow_queries": slow_queries,
                        "rejected_connections": rejected_connections,
                        "innodb_row_lock_waits": innodb_row_lock_waits,
                        "innodb_row_lock_time_ms": innodb_row_lock_time_ms,
                        },
                        metric="connection_percent",
                        label="DB connections",
                        unit="%",
                        warn=warn_percent,
                        fail=fail_percent,
                    ),
                )
            )
        except Exception as exc:
            checks.append(
                result(
                    "mysql",
                    f"{target['name']} MySQL/MariaDB health",
                    "fail",
                    "high",
                    f"MySQL/MariaDB check failed for {target['safe_target']}.",
                    {"target": target["safe_target"], "error": str(exc)},
                )
            )
        finally:
            if cursor is not None:
                cursor.close()
            if conn is not None:
                conn.close()
    return checks


def check_clickhouse() -> list[dict[str, Any]]:
    urls = env_items("ROOTTRACE_CLICKHOUSE_URL", "ROOTTRACE_CLICKHOUSE_URLS")
    for _, host, port in parse_host_port_targets(env("ROOTTRACE_CLICKHOUSE_TARGETS"), 8123, "clickhouse"):
        urls.append(f"http://{host}:{port}")
    if not urls:
        return []
    headers = {}
    username = env("ROOTTRACE_CLICKHOUSE_USERNAME")
    password = env("ROOTTRACE_CLICKHOUSE_PASSWORD")
    if username or password:
        headers["Authorization"] = auth_header(username, password)
    checks: list[dict[str, Any]] = []
    for raw_url in urls:
        base_url = raw_url.rstrip("/")
        safe_url = redact_url_credentials(base_url)
        try:
            started = time.monotonic()
            ping = http_text(f"{base_url}/ping", headers=headers).strip()
            version = None
            active_queries = None
            try:
                version_payload = http_json(
                    f"{base_url}/?query={quote('SELECT version() AS version FORMAT JSON', safe='')}",
                    headers=headers,
                )
                rows = version_payload.get("data", []) if isinstance(version_payload, dict) else []
                version = rows[0].get("version") if rows else None
            except Exception:
                pass
            try:
                metrics_query = "SELECT metric, value FROM system.metrics WHERE metric IN ('Query') FORMAT JSON"
                metrics_payload = http_json(
                    f"{base_url}/?query={quote(metrics_query, safe='')}",
                    headers=headers,
                )
                rows = metrics_payload.get("data", []) if isinstance(metrics_payload, dict) else []
                for row in rows:
                    if row.get("metric") == "Query":
                        active_queries = int(row.get("value", 0) or 0)
            except Exception:
                pass
            elapsed_ms = round((time.monotonic() - started) * 1000, 2)
            ok = ping.lower().startswith("ok")
            checks.append(
                result(
                    "clickhouse",
                    "ClickHouse HTTP health",
                    "pass" if ok else "warn",
                    "low" if ok else "medium",
                    f"ClickHouse HTTP ping returned {ping or 'an empty response'}.",
                    {
                        "url": safe_url,
                        "latency_ms": elapsed_ms,
                        "version": version,
                        "active_queries": active_queries,
                    },
                )
            )
        except Exception as exc:
            checks.append(
                result(
                    "clickhouse",
                    "ClickHouse HTTP health",
                    "fail",
                    "high",
                    f"ClickHouse check failed for {safe_url}.",
                    {"url": safe_url, "error": str(exc)},
                )
            )
    return checks


def check_cassandra() -> list[dict[str, Any]]:
    contact_points = env_items("ROOTTRACE_CASSANDRA_CONTACT_POINTS", "ROOTTRACE_CASSANDRA_TARGETS")
    if not contact_points:
        return []
    try:
        from cassandra.auth import PlainTextAuthProvider  # type: ignore
        from cassandra.cluster import Cluster  # type: ignore
    except Exception:
        return [
            result(
                "cassandra",
                "Cassandra dependency",
                "unknown",
                "medium",
                "Install cassandra-driver in the collector host environment to enable read-only Cassandra system table checks.",
                {"contact_points": contact_points, "dependency": "cassandra-driver"},
            )
        ]
    hosts: list[str] = []
    port = env_int("ROOTTRACE_CASSANDRA_PORT", 9042)
    for item in contact_points:
        if ":" in item:
            host, raw_port = item.rsplit(":", 1)
            hosts.append(host)
            try:
                port = int(raw_port)
            except ValueError:
                pass
        else:
            hosts.append(item)
    auth_provider = None
    username = env("ROOTTRACE_CASSANDRA_USERNAME")
    password = env("ROOTTRACE_CASSANDRA_PASSWORD")
    if username or password:
        auth_provider = PlainTextAuthProvider(username=username, password=password)
    cluster = None
    try:
        started = time.monotonic()
        cluster_kwargs: dict[str, Any] = {
            "contact_points": hosts,
            "port": port,
            "connect_timeout": env_float("ROOTTRACE_CASSANDRA_TIMEOUT_SECONDS", CHECK_TIMEOUT_SECONDS),
        }
        local_dc = env("ROOTTRACE_CASSANDRA_LOCAL_DATACENTER")
        if local_dc:
            cluster_kwargs["local_dc"] = local_dc
        if auth_provider:
            cluster_kwargs["auth_provider"] = auth_provider
        cluster = Cluster(**cluster_kwargs)
        session = cluster.connect()
        session.default_timeout = env_float("ROOTTRACE_CASSANDRA_TIMEOUT_SECONDS", CHECK_TIMEOUT_SECONDS)
        row = session.execute("SELECT release_version, cluster_name, data_center, rack FROM system.local").one()
        peers = list(session.execute("SELECT peer, data_center FROM system.peers"))
        elapsed_ms = round((time.monotonic() - started) * 1000, 2)
        return [
            result(
                "cassandra",
                "Cassandra system table health",
                "pass",
                "low",
                f"Cassandra system.local responded in {elapsed_ms} ms.",
                {
                    "contact_points": hosts,
                    "port": port,
                    "latency_ms": elapsed_ms,
                    "cluster_name": getattr(row, "cluster_name", None),
                    "release_version": getattr(row, "release_version", None),
                    "data_center": getattr(row, "data_center", None),
                    "rack": getattr(row, "rack", None),
                    "peer_count": len(peers),
                },
            )
        ]
    except Exception as exc:
        return [
            result(
                "cassandra",
                "Cassandra system table health",
                "fail",
                "high",
                "Cassandra check failed.",
                {"contact_points": hosts, "port": port, "error": str(exc)},
            )
        ]
    finally:
        if cluster is not None:
            cluster.shutdown()


def redis_command(sock: socket.socket, *parts: str) -> Any:
    encoded = [part.encode("utf-8") for part in parts]
    request = [f"*{len(encoded)}\r\n".encode("ascii")]
    for item in encoded:
        request.append(f"${len(item)}\r\n".encode("ascii"))
        request.append(item + b"\r\n")
    sock.sendall(b"".join(request))
    return redis_read(sock)


def redis_read(sock: socket.socket) -> Any:
    prefix = sock.recv(1)
    if not prefix:
        raise RuntimeError("Redis closed the connection.")

    def read_line() -> bytes:
        data = b""
        while not data.endswith(b"\r\n"):
            part = sock.recv(1)
            if not part:
                raise RuntimeError("Redis response ended early.")
            data += part
        return data[:-2]

    if prefix == b"+":
        return read_line().decode("utf-8", errors="replace")
    if prefix == b"-":
        raise RuntimeError(read_line().decode("utf-8", errors="replace"))
    if prefix == b":":
        return int(read_line())
    if prefix == b"$":
        length = int(read_line())
        if length < 0:
            return None
        data = b""
        while len(data) < length + 2:
            data += sock.recv(length + 2 - len(data))
        return data[:length].decode("utf-8", errors="replace")
    raise RuntimeError("Unsupported Redis response type.")


def parse_redis_info(raw: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in raw.splitlines():
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        values[key] = value
    return values


def check_redis() -> list[dict[str, Any]]:
    targets = parse_host_port_targets(env("ROOTTRACE_REDIS_TARGETS"), 6379, "redis")
    if not targets:
        return []
    checks = []
    password = env("ROOTTRACE_REDIS_PASSWORD")
    timeout = env_float("ROOTTRACE_REDIS_TIMEOUT_SECONDS", CHECK_TIMEOUT_SECONDS)
    for name, host, port in targets:
        try:
            started = time.monotonic()
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                if password:
                    redis_command(sock, "AUTH", password)
                pong = redis_command(sock, "PING")
                memory = parse_redis_info(redis_command(sock, "INFO", "memory"))
                clients = parse_redis_info(redis_command(sock, "INFO", "clients"))
                stats = parse_redis_info(redis_command(sock, "INFO", "stats"))
                replication = parse_redis_info(redis_command(sock, "INFO", "replication"))
            elapsed_ms = round((time.monotonic() - started) * 1000, 2)
            used_memory = int(memory.get("used_memory", "0") or 0)
            maxmemory = int(memory.get("maxmemory", "0") or 0)
            memory_percent = round((used_memory / maxmemory) * 100, 2) if maxmemory > 0 else None
            evicted_keys = int(stats.get("evicted_keys", "0") or 0)
            rejected_connections = int(stats.get("rejected_connections", "0") or 0)
            blocked_clients = int(clients.get("blocked_clients", "0") or 0)
            status = "pass"
            severity = "low"
            if memory_percent is not None:
                status, severity = threshold_status(
                    memory_percent,
                    env_float("ROOTTRACE_REDIS_MEMORY_WARN_PERCENT", 80.0),
                    env_float("ROOTTRACE_REDIS_MEMORY_FAIL_PERCENT", 90.0),
                )
            if any((evicted_keys, rejected_connections, blocked_clients)) and status == "pass":
                status, severity = "warn", "medium"
            checks.append(
                result(
                    "redis",
                    f"{name} Redis health",
                    status,
                    severity,
                    f"Redis replied to PING with {pong}.",
                    with_thresholds(
                        {
                        "host": host,
                        "port": port,
                        "latency_ms": elapsed_ms,
                        "used_memory_bytes": used_memory,
                        "maxmemory_bytes": maxmemory or None,
                        "memory_percent": memory_percent,
                        "connected_clients": int(clients.get("connected_clients", "0") or 0),
                        "blocked_clients": blocked_clients,
                        "evicted_keys": evicted_keys,
                        "expired_keys": int(stats.get("expired_keys", "0") or 0),
                        "rejected_connections": rejected_connections,
                        "keyspace_hits": int(stats.get("keyspace_hits", "0") or 0),
                        "keyspace_misses": int(stats.get("keyspace_misses", "0") or 0),
                        "role": replication.get("role"),
                        "connected_slaves": int(replication.get("connected_slaves", "0") or 0),
                        "master_link_status": replication.get("master_link_status"),
                        "master_last_io_seconds_ago": int(replication.get("master_last_io_seconds_ago", "0") or 0)
                        if replication.get("master_last_io_seconds_ago") not in (None, "")
                        else None,
                        },
                        metric="memory_percent",
                        label="Memory used",
                        unit="%",
                        warn=env_float("ROOTTRACE_REDIS_MEMORY_WARN_PERCENT", 80.0),
                        fail=env_float("ROOTTRACE_REDIS_MEMORY_FAIL_PERCENT", 90.0),
                    ),
                )
            )
        except Exception as exc:
            checks.append(
                result(
                    "redis",
                    f"{name} Redis health",
                    "fail",
                    "high",
                    f"Redis check failed for {host}:{port}.",
                    {"host": host, "port": port, "error": str(exc)},
                )
            )
    return checks


def check_elasticsearch() -> list[dict[str, Any]]:
    urls = split_csv(env("ROOTTRACE_ELASTICSEARCH_URLS") or env("ROOTTRACE_ELASTICSEARCH_URL"))
    if not urls:
        return []
    checks = []
    headers = {}
    username = env("ROOTTRACE_ELASTICSEARCH_USERNAME")
    password = env("ROOTTRACE_ELASTICSEARCH_PASSWORD")
    if username or password:
        headers["Authorization"] = auth_header(username, password)
    for raw_url in urls:
        base_url = raw_url.rstrip("/")
        try:
            started = time.monotonic()
            health = http_json(f"{base_url}/_cluster/health", headers=headers)
            health_latency_ms = round((time.monotonic() - started) * 1000, 2)
            started = time.monotonic()
            indices = http_json(f"{base_url}/_cat/indices?format=json", headers=headers)
            index_latency_ms = round((time.monotonic() - started) * 1000, 2)
            node_stats: dict[str, Any] = {}
            try:
                stats_payload = http_json(f"{base_url}/_nodes/stats/jvm,fs,thread_pool,indices", headers=headers)
                nodes = (stats_payload.get("nodes") or {}) if isinstance(stats_payload, dict) else {}
                heap_values = []
                disk_values = []
                rejected_total = 0
                gc_time_ms = 0
                search_query_total = 0
                index_total = 0
                for node in nodes.values():
                    if not isinstance(node, dict):
                        continue
                    jvm = node.get("jvm") if isinstance(node.get("jvm"), dict) else {}
                    fs = node.get("fs") if isinstance(node.get("fs"), dict) else {}
                    thread_pool = node.get("thread_pool") if isinstance(node.get("thread_pool"), dict) else {}
                    indices_stats = node.get("indices") if isinstance(node.get("indices"), dict) else {}
                    heap_percent = ((jvm.get("mem") or {}).get("heap_used_percent") if isinstance(jvm.get("mem"), dict) else None)
                    if heap_percent is not None:
                        heap_values.append(float(heap_percent))
                    total_fs = fs.get("total") if isinstance(fs.get("total"), dict) else {}
                    disk_total = float(total_fs.get("total_in_bytes") or 0)
                    disk_available = float(total_fs.get("available_in_bytes") or 0)
                    if disk_total > 0:
                        disk_values.append(round(((disk_total - disk_available) / disk_total) * 100, 2))
                    pools = thread_pool.values() if isinstance(thread_pool, dict) else []
                    for pool in pools:
                        if isinstance(pool, dict):
                            rejected_total += int(pool.get("rejected") or 0)
                    collectors = (jvm.get("gc") or {}).get("collectors") if isinstance(jvm.get("gc"), dict) else {}
                    if isinstance(collectors, dict):
                        for collector in collectors.values():
                            if isinstance(collector, dict) and isinstance(collector.get("collection_time_in_millis"), (int, float)):
                                gc_time_ms += int(collector.get("collection_time_in_millis") or 0)
                    search = ((indices_stats.get("search") or {}) if isinstance(indices_stats.get("search"), dict) else {})
                    indexing = ((indices_stats.get("indexing") or {}) if isinstance(indices_stats.get("indexing"), dict) else {})
                    search_query_total += int(search.get("query_total") or 0)
                    index_total += int(indexing.get("index_total") or 0)
                node_stats = {
                    "jvm_heap_used_percent_max": round(max(heap_values), 2) if heap_values else None,
                    "disk_used_percent_max": round(max(disk_values), 2) if disk_values else None,
                    "thread_pool_rejected_total": rejected_total,
                    "gc_collection_time_ms_total": gc_time_ms,
                    "search_query_total": search_query_total,
                    "index_total": index_total,
                }
            except Exception:
                node_stats = {}
            unhealthy = [item.get("index") for item in indices if item.get("health") not in {"green", None}]
            cluster_status = health.get("status", "unknown")
            if cluster_status == "red" or unhealthy:
                status, severity = "fail", "critical"
            elif cluster_status == "yellow":
                status, severity = "warn", "medium"
            elif node_stats.get("jvm_heap_used_percent_max") is not None and float(node_stats["jvm_heap_used_percent_max"]) >= 85:
                status, severity = "warn", "medium"
            elif node_stats.get("disk_used_percent_max") is not None and float(node_stats["disk_used_percent_max"]) >= 85:
                status, severity = "warn", "medium"
            else:
                status, severity = "pass", "low"
            checks.append(
                result(
                    "elasticsearch",
                    "Elasticsearch cluster health",
                    status,
                    severity,
                    f"Elasticsearch cluster status is {cluster_status}.",
                    with_thresholds(
                        {
                            "url": base_url,
                            "cluster_name": health.get("cluster_name"),
                            "status": cluster_status,
                            "number_of_nodes": health.get("number_of_nodes"),
                            "number_of_data_nodes": health.get("number_of_data_nodes"),
                            "active_primary_shards": health.get("active_primary_shards"),
                            "active_shards": health.get("active_shards"),
                            "active_shards_percent": health.get("active_shards_percent_as_number"),
                            "relocating_shards": health.get("relocating_shards"),
                            "initializing_shards": health.get("initializing_shards"),
                            "unassigned_shards": health.get("unassigned_shards"),
                            "delayed_unassigned_shards": health.get("delayed_unassigned_shards"),
                            "number_of_pending_tasks": health.get("number_of_pending_tasks"),
                            "task_max_waiting_in_queue_millis": health.get("task_max_waiting_in_queue_millis"),
                            "indices_count": len(indices),
                            "unhealthy_indices_count": len(unhealthy),
                            "unhealthy_indices": unhealthy[:25],
                            "latency_ms": health_latency_ms,
                            "index_latency_ms": index_latency_ms,
                            **node_stats,
                        },
                        metric="active_shards_percent",
                        label="Active shards",
                        unit="%",
                        warn=99,
                        fail=95,
                        higher_is_worse=False,
                    ),
                )
            )
        except Exception as exc:
            checks.append(
                result(
                    "elasticsearch",
                    "Elasticsearch cluster health",
                    "fail",
                    "high",
                    f"Elasticsearch check failed for {base_url}.",
                    {"url": base_url, "error": str(exc)},
                )
            )
    return checks


def check_rabbitmq() -> list[dict[str, Any]]:
    api_url = env("ROOTTRACE_RABBITMQ_API_URL")
    if not api_url:
        return []
    checks: list[dict[str, Any]] = []
    username = env("ROOTTRACE_RABBITMQ_USERNAME")
    password = env("ROOTTRACE_RABBITMQ_PASSWORD")
    vhost = env("ROOTTRACE_RABBITMQ_VHOST", "/")
    headers = {"Authorization": auth_header(username, password)} if username or password else {}
    base = api_url.rstrip("/")
    try:
        queues = http_json(f"{base}/queues/{quote(vhost, safe='')}", headers=headers)
        nodes = []
        overview = {}
        try:
            nodes_payload = http_json(f"{base}/nodes", headers=headers)
            nodes = nodes_payload if isinstance(nodes_payload, list) else []
        except Exception:
            nodes = []
        try:
            overview_payload = http_json(f"{base}/overview", headers=headers)
            overview = overview_payload if isinstance(overview_payload, dict) else {}
        except Exception:
            overview = {}
        long_queues = []
        unsynced = []
        no_consumer_queues = []
        total_ready = 0
        total_unacked = 0
        threshold_ms = env_int("ROOTTRACE_RABBITMQ_DRAIN_WARN_MS", 900_000)
        for queue in queues:
            stats = queue.get("message_stats", {}) or {}
            ready = int(queue.get("messages_ready", 0) or 0)
            unacked = int(queue.get("messages_unacknowledged", 0) or 0)
            total = int(queue.get("messages", 0) or 0)
            total_ready += ready
            total_unacked += unacked
            consumers = int(queue.get("consumers", 0) or 0)
            deliver_rate = float((stats.get("deliver_details") or {}).get("rate", 0.0) or 0.0)
            drain_ms = int((ready / deliver_rate) * 1000) if deliver_rate > 0 else (300_000 if ready else 0)
            if drain_ms >= threshold_ms:
                long_queues.append({"name": queue.get("name"), "messages": total, "time_to_complete_ms": drain_ms})
            if total > 0 and consumers == 0:
                no_consumer_queues.append({"name": queue.get("name"), "messages": total})
            slave_nodes = queue.get("slave_nodes", []) or []
            synced_nodes = queue.get("synchronised_slave_nodes", []) or []
            if len(slave_nodes) > len(synced_nodes):
                unsynced.append(
                    {
                        "name": queue.get("name"),
                        "slave_nodes": slave_nodes,
                        "synchronised_slave_nodes": synced_nodes,
                    }
                )
        memory_alarm_nodes = [node.get("name") for node in nodes if node.get("mem_alarm")]
        disk_alarm_nodes = [node.get("name") for node in nodes if node.get("disk_free_alarm")]
        partitioned_nodes = [node.get("name") for node in nodes if node.get("partitions")]
        status = "fail" if unsynced or memory_alarm_nodes or disk_alarm_nodes or partitioned_nodes else "warn" if long_queues or no_consumer_queues else "pass"
        severity = "critical" if status == "fail" else "medium" if status == "warn" else "low"
        checks.append(
            result(
                "rabbitmq",
                "RabbitMQ queue health",
                status,
                severity,
                f"RabbitMQ has {len(long_queues)} long-draining queue(s), {len(unsynced)} unsynchronized mirror queue(s), and {len(memory_alarm_nodes) + len(disk_alarm_nodes)} node alarm(s).",
                {
                    "api_url": base,
                    "vhost": vhost,
                    "queue_count": len(queues),
                    "node_count": len(nodes),
                    "total_ready_messages": total_ready,
                    "total_unacknowledged_messages": total_unacked,
                    "high_queues": long_queues[:25],
                    "queues_without_consumers": no_consumer_queues[:25],
                    "unsynchronized_mirrors": unsynced[:25],
                    "memory_alarm_count": len(memory_alarm_nodes),
                    "disk_alarm_count": len(disk_alarm_nodes),
                    "partition_count": len(partitioned_nodes),
                    "memory_alarm_nodes": memory_alarm_nodes[:25],
                    "disk_alarm_nodes": disk_alarm_nodes[:25],
                    "partitioned_nodes": partitioned_nodes[:25],
                    "messages_published_rate": ((overview.get("message_stats") or {}).get("publish_details") or {}).get("rate")
                    if isinstance(overview.get("message_stats"), dict)
                    else None,
                    "messages_delivered_rate": ((overview.get("message_stats") or {}).get("deliver_get_details") or {}).get("rate")
                    if isinstance(overview.get("message_stats"), dict)
                    else None,
                },
            )
        )
    except Exception as exc:
        checks.append(
            result(
                "rabbitmq",
                "RabbitMQ queue health",
                "fail",
                "high",
                "RabbitMQ management API check failed.",
                {"api_url": base, "vhost": vhost, "error": str(exc)},
            )
        )
    return checks


def check_mongodb() -> list[dict[str, Any]]:
    mongodb_uri = env("ROOTTRACE_MONGODB_URI")
    target_items = [mongodb_uri] if mongodb_uri else split_csv(env("ROOTTRACE_MONGODB_TARGETS"))
    if not target_items:
        return []
    checks = []

    def number_or_none(value: Any) -> float | None:
        if value in (None, ""):
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def round_or_none(value: Any, digits: int = 2) -> float | None:
        number = number_or_none(value)
        return None if number is None else round(number, digits)

    def int_or_zero(value: Any) -> int:
        number = number_or_none(value)
        return 0 if number is None else int(number)

    def op_latency_ms(op_latencies: dict[str, Any], key: str) -> float | None:
        section = op_latencies.get(key) if isinstance(op_latencies, dict) else None
        if not isinstance(section, dict):
            return None
        latency_micros = number_or_none(section.get("latency"))
        ops = number_or_none(section.get("ops"))
        if latency_micros is None or not ops:
            return None
        return round(latency_micros / ops / 1000, 2)

    try:
        from pymongo import MongoClient  # type: ignore
        from pymongo.errors import OperationFailure, PyMongoError  # type: ignore
    except Exception:
        checks = []
        for item in target_items:
            uri = item if item.startswith("mongodb://") or item.startswith("mongodb+srv://") else f"mongodb://{item}"
            safe_uri = re.sub(r"//[^/@:]+(:[^/@]+)?@", "//[REDACTED]@", uri)
            checks.append(result(
                "mongodb",
                "MongoDB dependency",
                "unknown",
                "medium",
                "Install pymongo in the collector image to enable read-only MongoDB replica, latency, and connection checks.",
                {"target": safe_uri, "dependency": "pymongo"},
            ))
        return checks

    for item in target_items:
        uri = item if item.startswith("mongodb://") or item.startswith("mongodb+srv://") else f"mongodb://{item}"
        safe_uri = re.sub(r"//[^/@:]+(:[^/@]+)?@", "//[REDACTED]@", uri)
        client = None
        try:
            client = MongoClient(uri, serverSelectionTimeoutMS=env_int("ROOTTRACE_MONGODB_TIMEOUT_MS", 2000), directConnection=False)
            started = time.monotonic()
            client.admin.command("ping")
            elapsed_ms = round((time.monotonic() - started) * 1000, 2)
            server_status = client.admin.command("serverStatus")
            connections_raw = server_status.get("connections", {}) or {}
            connections = connections_raw if isinstance(connections_raw, dict) else {}
            current_connections = int_or_zero(connections.get("current"))
            available_connections = int_or_zero(connections.get("available"))
            max_connections = current_connections + available_connections
            connection_percent = round((current_connections / max_connections) * 100, 2) if max_connections else None

            op_latencies = server_status.get("opLatencies", {}) or {}
            read_latency_ms = op_latency_ms(op_latencies, "reads")
            write_latency_ms = op_latency_ms(op_latencies, "writes")
            command_latency_ms = op_latency_ms(op_latencies, "commands")
            latency_values = [value for value in (read_latency_ms, write_latency_ms, command_latency_ms) if value is not None]
            operation_latency_ms = max(latency_values) if latency_values else None

            opcounters_raw = server_status.get("opcounters", {}) or {}
            opcounters = opcounters_raw if isinstance(opcounters_raw, dict) else {}
            global_lock_raw = server_status.get("globalLock", {}) or {}
            global_lock = global_lock_raw if isinstance(global_lock_raw, dict) else {}
            current_queue = global_lock.get("currentQueue", {}) if isinstance(global_lock, dict) else {}
            queued_operations = int_or_zero(current_queue.get("total")) if isinstance(current_queue, dict) else 0
            queued_readers = int_or_zero(current_queue.get("readers")) if isinstance(current_queue, dict) else 0
            queued_writers = int_or_zero(current_queue.get("writers")) if isinstance(current_queue, dict) else 0
            mem_raw = server_status.get("mem", {}) or {}
            mem = mem_raw if isinstance(mem_raw, dict) else {}
            wired_tiger_raw = server_status.get("wiredTiger", {}) or {}
            wired_tiger = wired_tiger_raw if isinstance(wired_tiger_raw, dict) else {}
            wired_tiger_cache_raw = wired_tiger.get("cache", {}) or {}
            wired_tiger_cache = wired_tiger_cache_raw if isinstance(wired_tiger_cache_raw, dict) else {}
            cache_used_bytes = number_or_none(wired_tiger_cache.get("bytes currently in the cache"))
            cache_max_bytes = number_or_none(wired_tiger_cache.get("maximum bytes configured"))
            cache_dirty_bytes = number_or_none(wired_tiger_cache.get("tracked dirty bytes in the cache"))
            cache_used_percent = round((cache_used_bytes / cache_max_bytes) * 100, 2) if cache_used_bytes is not None and cache_max_bytes else None
            cache_dirty_percent = round((cache_dirty_bytes / cache_max_bytes) * 100, 2) if cache_dirty_bytes is not None and cache_max_bytes else None

            lag_ms = 0
            role = "standalone"
            initial_sync_any = False
            replica_set_name = None
            replica_member_count = 0
            secondary_count = 0
            unhealthy_member_count = 0
            initial_sync_member_count = 0
            lagging_member = None
            try:
                rs = client.admin.command("replSetGetStatus")
                replica_set_name = rs.get("set") or rs.get("setName")
                state = rs.get("myState")
                role = {1: "primary", 2: "secondary", 5: "startup2", 7: "arbiter"}.get(state, "other")
                primary_optime = None
                members = rs.get("members", []) or []
                replica_member_count = len(members)
                for member in members:
                    if member.get("stateStr") == "PRIMARY":
                        optime_date = member.get("optimeDate")
                        primary_optime = optime_date.timestamp() if hasattr(optime_date, "timestamp") else None
                    if member.get("stateStr") == "SECONDARY":
                        secondary_count += 1
                    if member.get("state") == 5:
                        initial_sync_member_count += 1
                    member_healthy = member.get("health") in (1, 1.0, True)
                    if member.get("stateStr") not in {"PRIMARY", "SECONDARY", "ARBITER"} or not member_healthy:
                        unhealthy_member_count += 1
                initial_sync_any = initial_sync_member_count > 0
                if primary_optime is not None:
                    for member in members:
                        if member.get("stateStr") == "SECONDARY":
                            optime_date = member.get("optimeDate")
                            if hasattr(optime_date, "timestamp"):
                                member_lag_ms = int(max(0, primary_optime - optime_date.timestamp()) * 1000)
                                if member_lag_ms >= lag_ms:
                                    lag_ms = member_lag_ms
                                    lagging_member = member.get("name")
            except OperationFailure:
                pass
            lag_warn_ms = env_int("ROOTTRACE_MONGODB_WARN_LAG_SECONDS", 5) * 1000
            lag_fail_ms = env_int("ROOTTRACE_MONGODB_MAX_LAG_SECONDS", 15) * 1000
            connection_warn_percent = env_float("ROOTTRACE_MONGODB_CONNECTION_WARN_PERCENT", 80.0)
            connection_fail_percent = env_float("ROOTTRACE_MONGODB_CONNECTION_FAIL_PERCENT", 90.0)
            ping_latency_warn_ms = env_float("ROOTTRACE_MONGODB_LATENCY_WARN_MS", 250.0)
            ping_latency_fail_ms = env_float("ROOTTRACE_MONGODB_LATENCY_FAIL_MS", 1000.0)
            operation_latency_warn_ms = env_float("ROOTTRACE_MONGODB_OPERATION_LATENCY_WARN_MS", 100.0)
            operation_latency_fail_ms = env_float("ROOTTRACE_MONGODB_OPERATION_LATENCY_FAIL_MS", 250.0)
            lag_warn = lag_ms > lag_warn_ms
            lag_fail = lag_ms > lag_fail_ms
            connection_warn = connection_percent is not None and connection_percent > connection_warn_percent
            ping_latency_warn = elapsed_ms > ping_latency_warn_ms
            operation_latency_warn = operation_latency_ms is not None and operation_latency_ms > operation_latency_warn_ms
            unhealthy_member_warn = unhealthy_member_count > 0
            status = "fail" if lag_fail or initial_sync_any else "warn" if any((
                lag_warn,
                unhealthy_member_warn,
                connection_warn,
                ping_latency_warn,
                operation_latency_warn,
            )) else "pass"
            severity = "critical" if lag_fail or initial_sync_any else "high" if lag_warn or unhealthy_member_warn else "medium" if status == "warn" else "low"
            result_name = "MongoDB replica lag, latency, and connection health"
            threshold_metric = "replication_lag_ms"
            threshold_label = "Replica lag"
            threshold_unit = "ms"
            threshold_warn = lag_warn_ms
            threshold_fail = lag_fail_ms
            if initial_sync_any:
                result_name = "MongoDB replica initial sync"
                threshold_metric = "initial_sync_member_count"
                threshold_label = "Initial sync members"
                threshold_unit = ""
                threshold_warn = 1
                threshold_fail = 1
            elif unhealthy_member_warn:
                result_name = "MongoDB replica member health"
                threshold_metric = "unhealthy_member_count"
                threshold_label = "Unhealthy members"
                threshold_unit = ""
                threshold_warn = 1
                threshold_fail = 1
            elif lag_warn or lag_fail:
                result_name = "MongoDB replica lag"
            elif ping_latency_warn:
                result_name = "MongoDB ping latency"
                threshold_metric = "latency_ms"
                threshold_label = "Ping latency"
                threshold_unit = "ms"
                threshold_warn = ping_latency_warn_ms
                threshold_fail = ping_latency_fail_ms
            elif operation_latency_warn:
                result_name = "MongoDB operation latency"
                threshold_metric = "operation_latency_ms"
                threshold_label = "Operation latency"
                threshold_unit = "ms"
                threshold_warn = operation_latency_warn_ms
                threshold_fail = operation_latency_fail_ms
            elif connection_warn:
                result_name = "MongoDB connection usage"
                threshold_metric = "connection_percent"
                threshold_label = "Connections"
                threshold_unit = "%"
                threshold_warn = connection_warn_percent
                threshold_fail = connection_fail_percent
            checks.append(
                result(
                    "mongodb",
                    result_name,
                    status,
                    severity,
                    f"MongoDB role is {role}; max replica lag is {lag_ms} ms; ping latency is {elapsed_ms} ms.",
                    with_thresholds(
                        {
                            "target": safe_uri,
                            "role": role,
                            "replica_set_name": replica_set_name,
                            "replica_member_count": replica_member_count,
                            "secondary_count": secondary_count,
                            "unhealthy_member_count": unhealthy_member_count,
                            "initial_sync_member_count": initial_sync_member_count,
                            "lagging_member": lagging_member,
                            "connections_current": current_connections,
                            "connections_available": available_connections,
                            "connection_percent": connection_percent,
                            "latency_ms": elapsed_ms,
                            "read_latency_ms": read_latency_ms,
                            "write_latency_ms": write_latency_ms,
                            "command_latency_ms": command_latency_ms,
                            "operation_latency_ms": operation_latency_ms,
                            "operation_latency_warn_ms": operation_latency_warn_ms,
                            "queued_operations": queued_operations,
                            "queued_readers": queued_readers,
                            "queued_writers": queued_writers,
                            "opcounters_insert": int_or_zero(opcounters.get("insert")),
                            "opcounters_query": int_or_zero(opcounters.get("query")),
                            "opcounters_update": int_or_zero(opcounters.get("update")),
                            "opcounters_delete": int_or_zero(opcounters.get("delete")),
                            "opcounters_command": int_or_zero(opcounters.get("command")),
                            "resident_memory_mb": round_or_none(mem.get("resident")),
                            "virtual_memory_mb": round_or_none(mem.get("virtual")),
                            "wiredtiger_cache_used_percent": cache_used_percent,
                            "wiredtiger_cache_dirty_percent": cache_dirty_percent,
                            "replication_lag_ms": lag_ms,
                            "initial_sync_any": initial_sync_any,
                        },
                        metric=threshold_metric,
                        label=threshold_label,
                        unit=threshold_unit,
                        warn=threshold_warn,
                        fail=threshold_fail,
                    ),
                )
            )
        except PyMongoError as exc:
            checks.append(
                result(
                    "mongodb",
                    "MongoDB replica lag, latency, and connection health",
                    "fail",
                    "high",
                    "MongoDB check failed.",
                    {"target": safe_uri, "error": str(exc)},
                )
            )
        finally:
            if client is not None:
                client.close()
    return checks


def check_nvidia() -> list[dict[str, Any]]:
    if not env_bool("ROOTTRACE_NVIDIA_CHECKS", shutil.which("nvidia-smi") is not None):
        return []
    nvidia_smi = shutil.which("nvidia-smi")
    if not nvidia_smi:
        return [result("nvidia", "NVIDIA GPU metrics", "unknown", "low", "nvidia-smi is not available.", {})]
    try:
        completed = subprocess.run(
            [
                nvidia_smi,
                "--query-gpu=index,utilization.gpu,memory.used,memory.total,temperature.gpu",
                "--format=csv,noheader,nounits",
            ],
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [result("nvidia", "NVIDIA GPU metrics", "unknown", "low", "Could not run nvidia-smi.", {"error": str(exc)})]
    if completed.returncode != 0:
        return [result("nvidia", "NVIDIA GPU metrics", "unknown", "low", "nvidia-smi returned a non-zero status.", {"returncode": completed.returncode})]
    metrics = []
    for line in completed.stdout.splitlines():
        fields = [part.strip() for part in line.split(",")]
        if len(fields) < 5:
            continue
        try:
            index = int(fields[0])
            utilization = int(fields[1])
            memory_used = int(fields[2])
            memory_total = int(fields[3])
            temperature = int(fields[4])
        except ValueError:
            continue
        metrics.append(
            {
                "index": index,
                "utilization_percent": utilization,
                "memory_percent": round((memory_used / memory_total) * 100, 2) if memory_total else 0,
                "temperature_celsius": temperature,
            }
        )
    if not metrics:
        return [result("nvidia", "NVIDIA GPU metrics", "unknown", "low", "No GPU metrics could be parsed.", {})]
    memory_warn = env_float("ROOTTRACE_NVIDIA_MEMORY_WARN_PERCENT", 90.0)
    memory_fail = env_float("ROOTTRACE_NVIDIA_MEMORY_FAIL_PERCENT", 95.0)
    temp_fail = env_int("ROOTTRACE_NVIDIA_TEMP_FAIL_C", 90)
    return [
        result(
            "nvidia",
            f"NVIDIA GPU {item['index']}",
            "fail"
            if item["temperature_celsius"] >= temp_fail or item["memory_percent"] >= memory_fail
            else "warn"
            if item["memory_percent"] >= memory_warn
            else "pass",
            "critical"
            if item["temperature_celsius"] >= temp_fail or item["memory_percent"] >= memory_fail
            else "medium"
            if item["memory_percent"] >= memory_warn
            else "low",
            f"GPU {item['index']} memory is {item['memory_percent']}% and temperature is {item['temperature_celsius']} C.",
            with_thresholds(
                {
                    "gpu": f"GPU {item['index']}",
                    "index": item["index"],
                    "gpu_count": len(metrics),
                    "utilization_percent": item["utilization_percent"],
                    "memory_percent": item["memory_percent"],
                    "temperature_celsius": item["temperature_celsius"],
                    "temperature_fail_celsius": temp_fail,
                },
                metric="memory_percent",
                label="GPU memory",
                unit="%",
                warn=memory_warn,
                fail=memory_fail,
            ),
        )
        for item in metrics
    ]


def custom_metric_paths() -> list[Path]:
    paths: list[Path] = []
    for raw_path in env_items("ROOTTRACE_CUSTOM_METRICS_PATH", "ROOTTRACE_CUSTOM_METRICS_PATHS"):
        path = Path(raw_path).expanduser()
        if path.exists():
            paths.append(path)
    return paths


def custom_metric_modules() -> list[Path]:
    modules: list[Path] = []
    seen: set[str] = set()
    max_files = max(env_int("ROOTTRACE_CUSTOM_METRICS_MAX_FILES", 16), 1)
    for path in custom_metric_paths():
        candidates = [path]
        if path.is_dir():
            try:
                candidates = sorted(
                    item
                    for item in path.iterdir()
                    if item.is_file() and item.suffix == ".py" and not item.name.startswith(("_", "."))
                )
            except OSError:
                candidates = []
        for candidate in candidates:
            if candidate.suffix != ".py":
                continue
            resolved = str(candidate.resolve())
            if resolved in seen:
                continue
            seen.add(resolved)
            modules.append(candidate)
            if len(modules) >= max_files:
                return modules
    return modules


def load_custom_metric_module(path: Path):
    module_name = f"roottrace_custom_{sha256_short(str(path.resolve()))}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not create import spec")
    module = importlib.util.module_from_spec(spec)
    parent = str(path.parent.resolve())
    sys.path.insert(0, parent)
    try:
        spec.loader.exec_module(module)
    finally:
        try:
            sys.path.remove(parent)
        except ValueError:
            pass
    return module


def _custom_metric_collector_callable(module: Any) -> Callable[..., Any] | None:
    for name in ("collect_metrics", "collect", "roottrace_collect"):
        candidate = getattr(module, name, None)
        if callable(candidate):
            return candidate
    return None


def run_custom_metric_module(path: Path) -> list[dict[str, Any]]:
    emitted: list[dict[str, Any]] = []
    source = str(path)

    def emit(*args: Any, **kwargs: Any) -> dict[str, Any] | None:
        if args and isinstance(args[0], dict) and not kwargs:
            emitted.extend(normalize_custom_metric_output(args[0], source=source))
            return None
        kwargs.setdefault("source", source)
        metric = custom_metric_result(*args, **kwargs)
        emitted.append(metric)
        return metric

    module = load_custom_metric_module(path)
    collector = _custom_metric_collector_callable(module)
    if collector is None:
        return [
            result(
                "custom.module_error",
                f"Custom metrics {path.name}",
                "unknown",
                "medium",
                f"{path.name} did not define collect_metrics, collect, or roottrace_collect.",
                {"custom_metric": True, "source": source},
            )
        ]

    signature = inspect.signature(collector)
    params = list(signature.parameters.values())
    if not params:
        returned = collector()
    elif params[0].kind is inspect.Parameter.KEYWORD_ONLY:
        returned = collector(emit=emit)
    else:
        returned = collector(emit)
    emitted.extend(normalize_custom_metric_output(returned, source=source))
    return emitted


def check_custom_metrics() -> list[dict[str, Any]]:
    configured_paths = env_items("ROOTTRACE_CUSTOM_METRICS_PATH", "ROOTTRACE_CUSTOM_METRICS_PATHS")
    modules = custom_metric_modules()
    if not modules:
        if configured_paths:
            return [
                result(
                    "custom.module_error",
                    "Custom metrics path",
                    "unknown",
                    "medium",
                    "Custom metrics were enabled, but no readable Python metric modules were found.",
                    {"custom_metric": True, "paths": configured_paths},
                )
            ]
        return []
    checks: list[dict[str, Any]] = []
    for module_path in modules:
        try:
            checks.extend(run_custom_metric_module(module_path))
        except Exception as exc:
            checks.append(
                result(
                    "custom.module_error",
                    f"Custom metrics {module_path.name}",
                    "unknown",
                    "medium",
                    f"Custom metrics module {module_path.name} failed before producing results.",
                    {"custom_metric": True, "source": str(module_path), "error": str(exc)},
                )
            )
    return checks


def check_ec2_metadata() -> list[dict[str, Any]]:
    if not env_bool("ROOTTRACE_EC2_METADATA_CHECK", detect_provider() == "ec2"):
        return []
    token = ec2_metadata_token()
    if not token:
        return [result("ec2", "EC2 metadata reachability", "unknown", "low", "EC2 metadata service is not reachable.", {})]
    instance_id = ec2_metadata("meta-data/instance-id", token)
    availability_zone = ec2_metadata("meta-data/placement/availability-zone", token)
    return [
        result(
            "ec2",
            "EC2 metadata reachability",
            "pass" if instance_id else "unknown",
            "low",
            "EC2 metadata service responded." if instance_id else "EC2 metadata service did not return an instance id.",
            {"instance_id": instance_id, "availability_zone": availability_zone},
        )
    ]


def docker_socket_candidates() -> list[str]:
    configured = env("ROOTTRACE_DOCKER_SOCKET")
    candidates = [configured] if configured else []
    candidates.extend(["/var/run/docker.sock", "/run/docker.sock"])
    seen = set()
    result_paths = []
    for path in candidates:
        if path and path not in seen:
            seen.add(path)
            result_paths.append(path)
    return result_paths


def docker_unix_get(socket_path: str, path: str) -> tuple[int, str]:
    request = f"GET {path} HTTP/1.1\r\nHost: docker\r\nAccept: application/json\r\nConnection: close\r\n\r\n".encode("ascii")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(CHECK_TIMEOUT_SECONDS)
        sock.connect(socket_path)
        sock.sendall(request)
        chunks = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    raw = b"".join(chunks).decode("utf-8", errors="replace")
    head, _, body = raw.partition("\r\n\r\n")
    status_line = head.splitlines()[0] if head else ""
    match = re.search(r"\s(\d{3})\s", status_line)
    return (int(match.group(1)) if match else 0), body


def docker_container_name(container: dict[str, Any]) -> str:
    raw_names = container.get("Names")
    if isinstance(raw_names, list) and raw_names:
        return str(raw_names[0]).lstrip("/") or "container"
    raw_name = container.get("Name")
    if raw_name:
        return str(raw_name).lstrip("/") or "container"
    short_id = str(container.get("Id") or "")[:12]
    return short_id or "container"


def docker_health_from_status(status_text: str) -> str | None:
    match = re.search(r"\((healthy|unhealthy|health: starting|starting)\)", status_text, re.IGNORECASE)
    if not match:
        return None
    value = match.group(1).lower()
    return "starting" if value == "health: starting" else value


def docker_exit_code_from_status(status_text: str) -> int | None:
    match = re.search(r"Exited \((-?\d+)\)", status_text, re.IGNORECASE)
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def docker_inspect_container(socket_path: str, container_id: str) -> dict[str, Any]:
    if not container_id:
        return {}
    status_code, body = docker_unix_get(socket_path, f"/containers/{quote(container_id, safe='')}/json")
    if status_code < 200 or status_code >= 300:
        return {}
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def docker_container_summary(
    container: dict[str, Any],
    *,
    inspect: dict[str, Any] | None = None,
) -> dict[str, Any]:
    status_text = str(container.get("Status") or "")
    state = str(container.get("State") or "").lower()
    inspected_state = inspect.get("State") if isinstance(inspect, dict) else None
    if isinstance(inspected_state, dict):
        state = str(inspected_state.get("Status") or state).lower()
    exit_code = docker_exit_code_from_status(status_text)
    health = docker_health_from_status(status_text)
    finished_at = None
    started_at = None
    oom_killed = None
    error_text = None
    restart_count = container.get("RestartCount")
    if isinstance(inspect, dict) and inspect:
        inspected_name = inspect.get("Name")
        if inspected_name and not container.get("Names"):
            container = {**container, "Name": inspected_name}
        if isinstance(inspected_state, dict):
            inspected_exit_code = inspected_state.get("ExitCode")
            if inspected_exit_code not in (None, ""):
                try:
                    exit_code = int(inspected_exit_code)
                except (TypeError, ValueError):
                    pass
            finished_at = inspected_state.get("FinishedAt")
            started_at = inspected_state.get("StartedAt")
            oom_killed = bool(inspected_state.get("OOMKilled")) if inspected_state.get("OOMKilled") is not None else None
            error_text = inspected_state.get("Error") or None
            health_data = inspected_state.get("Health")
            if isinstance(health_data, dict) and health_data.get("Status"):
                health = str(health_data.get("Status")).lower()
        if inspect.get("RestartCount") not in (None, ""):
            restart_count = inspect.get("RestartCount")
    summary = {
        "id": str(container.get("Id") or "")[:12],
        "name": docker_container_name(container),
        "image": container.get("Image"),
        "state": state or "unknown",
        "status": status_text,
        "health": health,
        "exit_code": exit_code,
        "created": container.get("Created"),
        "started_at": started_at,
        "finished_at": finished_at,
        "restart_count": restart_count,
        "oom_killed": oom_killed,
        "error": error_text,
    }
    return {key: value for key, value in summary.items() if value not in (None, "", [])}


def docker_container_inventory(socket_path: str) -> dict[str, Any]:
    status_code, body = docker_unix_get(socket_path, "/containers/json?all=1")
    if status_code < 200 or status_code >= 300:
        return {
            "status_code": status_code,
            "container_count": 0,
            "running_count": 0,
            "stopped_count": 0,
            "exited_nonzero_count": 0,
            "problem_container_count": 0,
        }
    try:
        containers = json.loads(body)
    except json.JSONDecodeError:
        containers = []
    if not isinstance(containers, list):
        containers = []
    inspect_limit = max(env_int("ROOTTRACE_DOCKER_INSPECT_LIMIT", 100), 0)
    report_limit = max(env_int("ROOTTRACE_DOCKER_REPORT_LIMIT", 30), 5)
    running_containers: list[dict[str, Any]] = []
    stopped_containers: list[dict[str, Any]] = []
    exited_nonzero_containers: list[dict[str, Any]] = []
    unhealthy_containers: list[dict[str, Any]] = []
    restarting_containers: list[dict[str, Any]] = []
    dead_containers: list[dict[str, Any]] = []
    exited_zero_count = 0
    inspect_count = 0
    inspect_errors = []
    for container in containers:
        if not isinstance(container, dict):
            continue
        state = str(container.get("State") or "").lower()
        status_text = str(container.get("Status") or "")
        exit_code = docker_exit_code_from_status(status_text)
        should_inspect = (
            state in {"exited", "dead", "restarting", "running"}
            and inspect_count < inspect_limit
            and (state != "running" or docker_health_from_status(status_text) in {None, "unhealthy", "starting"})
        )
        inspected = {}
        if should_inspect:
            try:
                inspected = docker_inspect_container(socket_path, str(container.get("Id") or ""))
                inspect_count += 1
            except OSError as exc:
                inspect_errors.append({"container": docker_container_name(container), "error": str(exc)})
        summary = docker_container_summary(container, inspect=inspected)
        state = str(summary.get("state") or state).lower()
        exit_code = summary.get("exit_code", exit_code)
        health = str(summary.get("health") or "").lower()
        if state == "running":
            running_containers.append(summary)
            if health == "unhealthy":
                unhealthy_containers.append(summary)
            elif health == "starting":
                restarting_containers.append(summary)
        elif state == "restarting":
            restarting_containers.append(summary)
            stopped_containers.append(summary)
        elif state == "dead":
            dead_containers.append(summary)
            stopped_containers.append(summary)
        else:
            stopped_containers.append(summary)
            if state == "exited" and exit_code == 0:
                exited_zero_count += 1
        if state in {"exited", "dead"} and isinstance(exit_code, int) and exit_code != 0:
            exited_nonzero_containers.append(summary)

    running_names = [str(item.get("name")) for item in running_containers if item.get("name")]
    exited_nonzero_names = [str(item.get("name")) for item in exited_nonzero_containers if item.get("name")]
    unhealthy_names = [str(item.get("name")) for item in unhealthy_containers if item.get("name")]
    restarting_names = [str(item.get("name")) for item in restarting_containers if item.get("name")]
    stopped_count = len(stopped_containers)
    problem_ids = {
        str(item.get("id") or item.get("name") or "")
        for item in (
            exited_nonzero_containers
            + unhealthy_containers
            + restarting_containers
            + dead_containers
        )
        if item.get("id") or item.get("name")
    }
    problem_count = len(problem_ids)
    return {
        "status_code": status_code,
        "container_count": len(containers),
        "running_count": len(running_containers),
        "stopped_count": stopped_count,
        "exited_zero_count": exited_zero_count,
        "exited_nonzero_count": len(exited_nonzero_containers),
        "unhealthy_count": len(unhealthy_containers),
        "restarting_count": len(restarting_containers),
        "dead_count": len(dead_containers),
        "problem_container_count": problem_count,
        "inspected_count": inspect_count,
        "inspect_limit": inspect_limit,
        "inspect_errors": inspect_errors[:10],
        "container_names": running_names[:report_limit],
        "running_container_names": ", ".join(running_names[:report_limit]),
        "running_containers": running_containers[:report_limit],
        "exited_nonzero_container_names": ", ".join(exited_nonzero_names[:report_limit]),
        "exited_nonzero_containers": exited_nonzero_containers[:report_limit],
        "unhealthy_container_names": ", ".join(unhealthy_names[:report_limit]),
        "unhealthy_containers": unhealthy_containers[:report_limit],
        "restarting_container_names": ", ".join(restarting_names[:report_limit]),
        "restarting_containers": restarting_containers[:report_limit],
    }


def check_docker() -> list[dict[str, Any]]:
    checks = []
    in_container = Path("/.dockerenv").exists() or "docker" in read_text(Path("/proc/1/cgroup")).lower()
    daemon_matches = process_matches(("dockerd", "containerd"))
    socket_paths = docker_socket_candidates()
    socket_state = [{"path": path, "present": Path(path).exists()} for path in socket_paths]
    socket_present = any(item["present"] for item in socket_state)
    docker_cli_present = shutil.which("docker") is not None
    docker_detected = in_container or bool(daemon_matches) or socket_present or docker_cli_present or env_bool("ROOTTRACE_DOCKER_CHECK", False)
    if docker_detected:
        checks.append(
            result(
                "docker",
                "Docker runtime context",
                "pass",
                "low",
                "Docker runtime signal detected." if docker_detected else "Docker runtime context check enabled.",
                with_thresholds(
                    {
                        "in_container": in_container,
                        "daemon_processes": daemon_matches,
                        "docker_cli_present": docker_cli_present,
                        "sockets": socket_state,
                        "container_count": 0,
                        "running_count": 0,
                        "exited_nonzero_count": 0,
                        "problem_container_count": 0,
                    },
                    metric="problem_container_count",
                    label="Problem containers",
                    unit="",
                    warn=1,
                    fail=1,
                ),
            )
        )
    api_enabled = env_bool("ROOTTRACE_DOCKER_API_CHECK", socket_present or bool(env("ROOTTRACE_DOCKER_SOCKET")))
    socket_path = next((item["path"] for item in socket_state if item["present"]), "")
    if api_enabled and socket_path:
        try:
            status_code, ping = docker_unix_get(socket_path, "/_ping")
            reachable = status_code == 200 and ping.strip() == "OK"
            inventory = docker_container_inventory(socket_path) if reachable else {
                "container_count": 0,
                "running_count": 0,
                "exited_nonzero_count": 0,
                "problem_container_count": 0,
            }
            problem_count = int(inventory.get("problem_container_count") or 0)
            exited_nonzero_count = int(inventory.get("exited_nonzero_count") or 0)
            running_count = int(inventory.get("running_count") or 0)
            status = "fail" if problem_count > 0 else "pass" if reachable else "warn"
            severity = "high" if problem_count > 0 else "low" if reachable else "medium"
            checks.append(
                result(
                    "docker",
                    "Docker API inventory",
                    status,
                    severity,
                    (
                        f"Docker reports {running_count} running container(s) and {exited_nonzero_count} container(s) exited with non-zero status."
                        if reachable
                        else "Docker API socket was present but did not respond normally."
                    ),
                    with_thresholds(
                        {
                            "socket": socket_path,
                            "api_status_code": status_code,
                            "api_reachable": reachable,
                            **inventory,
                        },
                        metric="problem_container_count",
                        label="Problem containers",
                        unit="",
                        warn=1,
                        fail=1,
                    ),
                )
            )
        except OSError as exc:
            checks.append(
                result(
                    "docker",
                    "Docker API inventory",
                    "warn",
                    "medium",
                    "Docker socket was present but not readable by the collector user.",
                    with_thresholds(
                        {
                            "socket": socket_path,
                            "error": str(exc),
                            "container_count": 0,
                            "running_count": 0,
                            "exited_nonzero_count": 0,
                            "problem_container_count": 0,
                        },
                        metric="problem_container_count",
                        label="Problem containers",
                        unit="",
                        warn=1,
                        fail=1,
                    ),
                )
            )
    elif api_enabled:
        checks.append(
            result(
                "docker",
                "Docker API inventory",
                "warn",
                "medium",
                "Docker API inventory was enabled, but no Docker socket was present.",
                with_thresholds(
                    {
                        "configured_sockets": socket_state,
                        "container_count": 0,
                        "running_count": 0,
                        "exited_nonzero_count": 0,
                        "problem_container_count": 0,
                    },
                    metric="problem_container_count",
                    label="Problem containers",
                    unit="",
                    warn=1,
                    fail=1,
                ),
            )
        )
    elif socket_present:
        exists = Path(socket_path).exists()
        checks.append(
            result(
                "docker",
                "Docker socket availability",
                "pass",
                "low",
                "Docker socket is present. API inventory is disabled by ROOTTRACE_DOCKER_API_CHECK=false.",
                with_thresholds(
                    {
                        "socket": socket_path,
                        "present": exists,
                        "api_inventory_enabled": False,
                        "container_count": 0,
                        "running_count": 0,
                        "exited_nonzero_count": 0,
                        "problem_container_count": 0,
                    },
                    metric="problem_container_count",
                    label="Problem containers",
                    unit="",
                    warn=1,
                    fail=1,
                ),
            )
        )
    return checks


KUBERNETES_STARTUP_FAILURE_REASONS = {
    "CrashLoopBackOff",
    "CreateContainerConfigError",
    "CreateContainerError",
    "ErrImagePull",
    "ImageInspectError",
    "ImagePullBackOff",
    "InvalidImageName",
    "OOMKilled",
    "RunContainerError",
}
KUBERNETES_TRANSIENT_STARTUP_REASONS = {"ContainerCreating", "PodInitializing"}
KUBERNETES_IGNORED_TERMINATION_REASONS = {"Completed"}


def split_kubeconfig_path_list(raw: str) -> list[str]:
    parts = [raw]
    for separator in (os.pathsep, ","):
        expanded: list[str] = []
        for part in parts:
            expanded.extend(part.split(separator))
        parts = expanded
    return [part.strip() for part in parts if part.strip()]


def kubernetes_kubeconfig_candidates(*, include_defaults: bool = True) -> list[Path]:
    raw_paths: list[str] = []
    for name in KUBERNETES_KUBECONFIG_ENV_NAMES:
        configured = env(name)
        if configured:
            raw_paths.extend(split_kubeconfig_path_list(configured))
    if include_defaults:
        raw_paths.extend(KUBERNETES_DEFAULT_KUBECONFIG_PATHS)

    candidates: list[Path] = []
    seen: set[str] = set()
    for raw_path in raw_paths:
        path = Path(raw_path).expanduser()
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        candidates.append(path)
    return candidates


def path_exists(path: Path) -> bool:
    try:
        return path.exists()
    except OSError:
        return False


def kubernetes_kubeconfig_available() -> bool:
    if any(env(name) for name in KUBERNETES_KUBECONFIG_ENV_NAMES):
        return True
    return any(path_exists(path) for path in kubernetes_kubeconfig_candidates())


def parse_kubeconfig_scalar(value: str) -> Any:
    text = value.strip()
    if text in {"", "null", "Null", "NULL", "~"}:
        return None
    if text in {"{}", "[]"}:
        return {} if text == "{}" else []
    if text.lower() == "true":
        return True
    if text.lower() == "false":
        return False
    if (text.startswith('"') and text.endswith('"')) or (text.startswith("'") and text.endswith("'")):
        return text[1:-1]
    return text


def split_kubeconfig_yaml_key_value(line: str) -> tuple[str, str] | None:
    if ":" not in line:
        return None
    key, value = line.split(":", 1)
    key = key.strip()
    if not key:
        return None
    return key, value.strip()


def parse_kubeconfig_yaml_subset(raw: str) -> dict[str, Any]:
    data: dict[str, Any] = {"clusters": [], "contexts": [], "users": []}
    section = ""
    current: dict[str, Any] | None = None
    nested_key = ""
    list_property_indent = 0

    for raw_line in raw.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        stripped = raw_line.strip()

        if indent == 0 and not stripped.startswith("-"):
            pair = split_kubeconfig_yaml_key_value(stripped)
            if pair is None:
                continue
            key, value = pair
            if key in {"clusters", "contexts", "users"}:
                section = key
                current = None
                nested_key = ""
                continue
            if key == "current-context":
                data[key] = parse_kubeconfig_scalar(value)
            section = "" if key not in {"clusters", "contexts", "users"} else key
            continue

        if section not in {"clusters", "contexts", "users"}:
            continue

        if stripped.startswith("- "):
            current = {}
            data[section].append(current)
            nested_key = ""
            list_property_indent = indent + 2
            remainder = stripped[2:].strip()
            if not remainder:
                continue
            pair = split_kubeconfig_yaml_key_value(remainder)
            if pair is None:
                continue
            key, value = pair
            if value == "":
                current[key] = {}
                nested_key = key
            else:
                current[key] = parse_kubeconfig_scalar(value)
            continue

        if current is None:
            continue
        pair = split_kubeconfig_yaml_key_value(stripped)
        if pair is None:
            continue
        key, value = pair
        if value == "":
            current[key] = {}
            nested_key = key
            continue
        if nested_key and indent > list_property_indent:
            nested = current.setdefault(nested_key, {})
            if isinstance(nested, dict):
                nested[key] = parse_kubeconfig_scalar(value)
            continue
        current[key] = parse_kubeconfig_scalar(value)
        if indent <= list_property_indent:
            nested_key = ""
    return data


def load_kubeconfig(path: Path) -> dict[str, Any]:
    raw = path.read_text(encoding="utf-8")
    stripped = raw.lstrip()
    if stripped.startswith("{"):
        loaded = json.loads(raw)
        if isinstance(loaded, dict):
            return loaded
    try:
        import yaml  # type: ignore
    except Exception:
        yaml = None
    if yaml is not None:
        loaded = yaml.safe_load(raw)
        if isinstance(loaded, dict):
            return loaded
    return parse_kubeconfig_yaml_subset(raw)


def kubeconfig_named_item(items: Any, name: str | None, nested_key: str) -> dict[str, Any] | None:
    if not isinstance(items, list):
        return None
    fallback = None
    for item in items:
        if not isinstance(item, dict):
            continue
        if fallback is None:
            nested = item.get(nested_key)
            fallback = nested if isinstance(nested, dict) else item
        if name and str(item.get("name") or "") == name:
            nested = item.get(nested_key)
            return nested if isinstance(nested, dict) else item
    return fallback


def resolve_kubeconfig_path(path: Path, value: Any) -> str | None:
    if not value:
        return None
    resolved = Path(str(value)).expanduser()
    if not resolved.is_absolute():
        resolved = path.parent / resolved
    return str(resolved)


def decode_kubeconfig_pem_data(value: Any, label: str) -> str:
    try:
        decoded = base64.b64decode("".join(str(value).split()), validate=True)
    except (binascii.Error, ValueError, TypeError) as exc:
        raise RuntimeError(f"kubeconfig {label} was not valid base64 data") from exc
    return decoded.decode("utf-8", errors="replace")


def load_kubeconfig_verify_locations(context: ssl.SSLContext, path: Path, cluster: dict[str, Any]) -> None:
    ca_data = cluster.get("certificate-authority-data")
    if ca_data:
        context.load_verify_locations(cadata=decode_kubeconfig_pem_data(ca_data, "certificate-authority-data"))
        return
    ca_path = resolve_kubeconfig_path(path, cluster.get("certificate-authority"))
    if ca_path:
        context.load_verify_locations(ca_path)


def kubeconfig_ssl_context(cluster: dict[str, Any]) -> ssl.SSLContext:
    context = ssl.create_default_context()
    if cluster.get("insecure-skip-tls-verify") is True:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def load_kubeconfig_cert_chain(context: ssl.SSLContext, path: Path, user: dict[str, Any]) -> None:
    cert_data = user.get("client-certificate-data")
    key_data = user.get("client-key-data")
    if cert_data and key_data:
        cert_file = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False)
        key_file = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False)
        cert_path = key_path = ""
        try:
            cert_path = cert_file.name
            key_path = key_file.name
            cert_file.write(decode_kubeconfig_pem_data(cert_data, "client-certificate-data"))
            key_file.write(decode_kubeconfig_pem_data(key_data, "client-key-data"))
            cert_file.close()
            key_file.close()
            context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        finally:
            for handle in (cert_file, key_file):
                try:
                    handle.close()
                except OSError:
                    pass
            for temp_path in (cert_path, key_path):
                if temp_path:
                    try:
                        os.unlink(temp_path)
                    except OSError:
                        pass
        return

    cert_path = resolve_kubeconfig_path(path, user.get("client-certificate"))
    key_path = resolve_kubeconfig_path(path, user.get("client-key"))
    if cert_path and key_path:
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)


def kubeconfig_context(config: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    context_name = env("ROOTTRACE_KUBECONFIG_CONTEXT") or env("ROOTTRACE_KEDA_KUBECONFIG_CONTEXT") or str(config.get("current-context") or "")
    context = kubeconfig_named_item(config.get("contexts"), context_name or None, "context") or {}
    cluster_name = str(context.get("cluster") or "")
    user_name = str(context.get("user") or "")
    cluster = kubeconfig_named_item(config.get("clusters"), cluster_name or None, "cluster")
    user = kubeconfig_named_item(config.get("users"), user_name or None, "user") or {}
    if not isinstance(cluster, dict) or not cluster.get("server"):
        raise RuntimeError("kubeconfig did not contain a Kubernetes API server for the selected context")
    return cluster, user


class KubernetesApiClient:
    def __init__(self, base_url: str, headers: dict[str, str], context: ssl.SSLContext, source: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.headers = headers
        self.context = context
        self.source = source

    def get_json(self, path: str, query: dict[str, str] | None = None) -> dict[str, Any]:
        target = f"{self.base_url}{path}"
        if query:
            target = f"{target}?{urlencode(query)}"
        headers = {"Accept": "application/json"}
        headers.update(self.headers)
        payload = http_json(target, headers=headers, timeout=CHECK_TIMEOUT_SECONDS, context=self.context)
        return payload if isinstance(payload, dict) else {}

    def tcp_endpoint(self) -> tuple[str, int] | None:
        parsed = urlparse(self.base_url)
        host = parsed.hostname
        if not host:
            return None
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return host, port


def kubernetes_service_account_client() -> KubernetesApiClient | None:
    host = env("KUBERNETES_SERVICE_HOST")
    port = env("KUBERNETES_SERVICE_PORT", "443")
    if not host or not KUBERNETES_TOKEN_PATH.exists():
        return None
    token = read_text(KUBERNETES_TOKEN_PATH).strip()
    if not token:
        return None
    context = ssl.create_default_context(cafile=str(KUBERNETES_CA_PATH)) if KUBERNETES_CA_PATH.exists() else ssl.create_default_context()
    return KubernetesApiClient(f"https://{host}:{port}", {"Authorization": f"Bearer {token}"}, context, "service_account")


def kubernetes_kubeconfig_client() -> KubernetesApiClient | None:
    configured_candidates = kubernetes_kubeconfig_candidates(include_defaults=False)
    candidates = kubernetes_kubeconfig_candidates()
    errors: list[str] = []
    existing = [path for path in candidates if path_exists(path)]
    if not existing:
        if configured_candidates:
            searched = ", ".join(str(path) for path in configured_candidates)
            raise RuntimeError(f"configured Kubernetes kubeconfig was not found. Searched: {searched}")
        return None

    for path in existing:
        try:
            config = load_kubeconfig(path)
            cluster, user = kubeconfig_context(config)
            context = kubeconfig_ssl_context(cluster)
            if cluster.get("insecure-skip-tls-verify") is not True:
                load_kubeconfig_verify_locations(context, path, cluster)
            headers: dict[str, str] = {}
            token = user.get("token")
            token_file = resolve_kubeconfig_path(path, user.get("tokenFile") or user.get("token-file"))
            if not token and token_file:
                token = Path(token_file).read_text(encoding="utf-8").strip()
            if token:
                headers["Authorization"] = f"Bearer {token}"
            elif user.get("username") and user.get("password"):
                raw_auth = f"{user['username']}:{user['password']}".encode("utf-8")
                headers["Authorization"] = f"Basic {base64.b64encode(raw_auth).decode('ascii')}"
            load_kubeconfig_cert_chain(context, path, user)
            if not headers and not (
                user.get("client-certificate")
                or user.get("client-key")
                or user.get("client-certificate-data")
                or user.get("client-key-data")
            ):
                raise RuntimeError("kubeconfig user did not include token, basic auth, or client certificate credentials")
            return KubernetesApiClient(str(cluster["server"]), headers, context, f"kubeconfig:{path}")
        except Exception as exc:
            errors.append(f"{path}: {exc}")

    if errors:
        raise RuntimeError(f"could not load a Kubernetes kubeconfig. Errors: {'; '.join(errors)}")
    return None


def kubernetes_api_client() -> KubernetesApiClient | None:
    if any(env(name) for name in KUBERNETES_KUBECONFIG_ENV_NAMES):
        kubeconfig_client = kubernetes_kubeconfig_client()
        if kubeconfig_client is not None:
            return kubeconfig_client
    service_account_client = kubernetes_service_account_client()
    if service_account_client is not None:
        return service_account_client
    return kubernetes_kubeconfig_client()


def parse_kubernetes_timestamp(raw: Any) -> datetime | None:
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def pod_metadata(pod: dict[str, Any]) -> dict[str, Any]:
    metadata = pod.get("metadata") or {}
    spec = pod.get("spec") or {}
    status = pod.get("status") or {}
    return {
        "namespace": metadata.get("namespace") or "default",
        "name": metadata.get("name") or "pod",
        "uid": metadata.get("uid"),
        "node": spec.get("nodeName"),
        "phase": status.get("phase") or "Unknown",
        "created_at": metadata.get("creationTimestamp"),
    }


def pod_key(pod: dict[str, Any]) -> str:
    metadata = pod_metadata(pod)
    return f"{metadata['namespace']}/{metadata['name']}/{metadata.get('uid') or ''}"


def pod_age_minutes(pod: dict[str, Any], now: datetime) -> float | None:
    created_at = parse_kubernetes_timestamp((pod.get("metadata") or {}).get("creationTimestamp"))
    if created_at is None:
        return None
    return round(max(0.0, (now - created_at).total_seconds() / 60), 2)


def pod_startup_problems(
    pod: dict[str, Any],
    *,
    startup_grace_minutes: float,
    system_pod: bool,
    now: datetime,
) -> list[dict[str, Any]]:
    metadata = pod_metadata(pod)
    status = pod.get("status") or {}
    phase = str(metadata["phase"])
    phase_lower = phase.lower()
    age_minutes = pod_age_minutes(pod, now)
    older_than_grace = age_minutes is not None and age_minutes >= startup_grace_minutes
    problems: list[dict[str, Any]] = []

    if phase_lower == "failed":
        problems.append({"reason": "PodFailed", "message": "Pod phase is Failed.", "source": "pod_phase"})
    elif phase_lower == "pending" and older_than_grace:
        problems.append(
            {
                "reason": "PodPending",
                "message": f"Pod phase is Pending for {age_minutes if age_minutes is not None else 'unknown'} minute(s).",
                "source": "pod_phase",
            }
        )

    for status_key in ("initContainerStatuses", "containerStatuses"):
        for container in status.get(status_key, []) or []:
            container_name = container.get("name") or "container"
            state = container.get("state") or {}
            waiting = state.get("waiting") or {}
            terminated = state.get("terminated") or {}
            reason = waiting.get("reason")
            if reason:
                message = waiting.get("message") or f"{container_name} is waiting with reason {reason}."
                reason_is_failure = reason in KUBERNETES_STARTUP_FAILURE_REASONS
                reason_is_stale_startup = reason in KUBERNETES_TRANSIENT_STARTUP_REASONS and older_than_grace
                reason_is_system_problem = system_pod and reason not in KUBERNETES_TRANSIENT_STARTUP_REASONS
                if reason_is_failure or reason_is_stale_startup or reason_is_system_problem:
                    problems.append(
                        {
                            "reason": reason,
                            "message": message,
                            "container": container_name,
                            "source": status_key,
                        }
                    )
            terminated_reason = terminated.get("reason")
            if terminated_reason and terminated_reason not in KUBERNETES_IGNORED_TERMINATION_REASONS:
                if system_pod or terminated_reason in KUBERNETES_STARTUP_FAILURE_REASONS:
                    problems.append(
                        {
                            "reason": terminated_reason,
                            "message": terminated.get("message") or f"{container_name} terminated with reason {terminated_reason}.",
                            "container": container_name,
                            "exit_code": terminated.get("exitCode"),
                            "source": status_key,
                        }
                    )

    if system_pod:
        for condition in status.get("conditions", []) or []:
            condition_type = condition.get("type") or "PodCondition"
            condition_status = str(condition.get("status") or "").lower()
            reason = condition.get("reason") or f"{condition_type}NotReady"
            message = condition.get("message") or f"Pod condition {condition_type} is {condition.get('status')}."
            startup_condition = condition_type in {"PodScheduled", "Initialized", "Ready", "ContainersReady"}
            condition_is_bad = condition_status in {"false", "unknown"}
            if startup_condition and condition_is_bad and (older_than_grace or reason == "Unschedulable"):
                problems.append(
                    {
                        "reason": reason,
                        "message": message,
                        "condition": condition_type,
                        "source": "pod_condition",
                    }
                )

    if system_pod and older_than_grace and phase_lower not in {"running", "succeeded"}:
        if not any(problem["reason"] == "SystemPodNotRunning" for problem in problems):
            problems.append(
                {
                    "reason": "SystemPodNotRunning",
                    "message": f"System pod is {phase} after {age_minutes} minute(s).",
                    "source": "pod_phase",
                }
            )

    return problems


def summarize_kubernetes_pods(
    pods: list[dict[str, Any]],
    *,
    startup_grace_minutes: float,
    system_pod: bool = False,
    max_items: int = 20,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    phases: dict[str, int] = {}
    reasons: dict[str, int] = {}
    failing_pods: list[dict[str, Any]] = []
    failing_pod_count = 0
    pending = 0
    for pod in pods:
        metadata = pod_metadata(pod)
        phase = str(metadata["phase"]).lower()
        phases[phase] = phases.get(phase, 0) + 1
        if phase == "pending":
            pending += 1
        problems = pod_startup_problems(
            pod,
            startup_grace_minutes=startup_grace_minutes,
            system_pod=system_pod,
            now=now,
        )
        for problem in problems:
            reason = str(problem.get("reason") or "Unknown")
            reasons[reason] = reasons.get(reason, 0) + 1
        if problems:
            failing_pod_count += 1
            if len(failing_pods) < max_items:
                failing_pods.append(
                    {
                        "namespace": metadata["namespace"],
                        "pod": metadata["name"],
                        "node": metadata.get("node"),
                        "phase": metadata["phase"],
                        "age_minutes": pod_age_minutes(pod, now),
                        "problems": problems,
                    }
                )
    return {
        "inspected_pods": len(pods),
        "phases": phases,
        "reasons": reasons,
        "pending": pending,
        "failing_pods": failing_pods,
        "failing_pod_count": failing_pod_count,
    }


def dedupe_pods(pods: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[str, dict[str, Any]] = {}
    for pod in pods:
        deduped[pod_key(pod)] = pod
    return list(deduped.values())


def check_kubernetes() -> list[dict[str, Any]]:
    if not check_enabled("kubernetes"):
        return []
    host = env("KUBERNETES_SERVICE_HOST")
    port = env("KUBERNETES_SERVICE_PORT", "443")
    checks: list[dict[str, Any]] = []
    if host:
        checks.append(
            result(
                "kubernetes",
                "Kubernetes service account",
                "pass" if KUBERNETES_TOKEN_PATH.exists() else "warn",
                "low" if KUBERNETES_TOKEN_PATH.exists() else "medium",
                "Kubernetes service account token is present." if KUBERNETES_TOKEN_PATH.exists() else "Kubernetes service account token is not mounted.",
                {"service_account_token_present": KUBERNETES_TOKEN_PATH.exists()},
            )
        )

    try:
        client = kubernetes_api_client()
    except Exception as exc:
        if checks or kubernetes_kubeconfig_available() or explicitly_enabled("kubernetes"):
            checks.append(
                result(
                    "kubernetes",
                    "Kubernetes authentication",
                    "unknown",
                    "medium",
                    "Could not load Kubernetes API credentials.",
                    {"error": str(exc)},
                )
            )
        return checks

    if client is None and not host:
        return []

    if client is not None and client.source != "service_account":
        checks.append(
            result(
                "kubernetes",
                "Kubernetes authentication",
                "pass",
                "low",
                "Kubernetes kubeconfig authentication is configured.",
                {"auth_source": client.source},
            )
        )

    endpoint = client.tcp_endpoint() if client is not None else (host, int(port) if str(port).isdigit() else 443)
    if endpoint:
        api_host, api_port = endpoint
        try:
            with socket.create_connection((api_host, api_port), timeout=1.5):
                checks.append(result("kubernetes", "Kubernetes API reachability", "pass", "low", "Kubernetes API is reachable.", {"host": api_host, "port": api_port}))
        except OSError as exc:
            checks.append(result("kubernetes", "Kubernetes API reachability", "fail", "high", "Kubernetes API is not reachable.", {"host": api_host, "port": api_port, "error": str(exc)}))
    if env_bool("ROOTTRACE_KUBERNETES_POD_CHECKS", True) and client is not None:
        try:
            raw_node = env("ROOTTRACE_HOSTNAME", socket.gethostname())
            pods = client.get_json("/api/v1/pods", {"fieldSelector": f"spec.nodeName={raw_node}"})
            node_pods = list(pods.get("items", []) or [])
            startup_grace_minutes = env_float("ROOTTRACE_KUBERNETES_STARTUP_GRACE_MINUTES", 10.0)
            max_evidence = env_int("ROOTTRACE_KUBERNETES_MAX_POD_EVIDENCE", 20)
            node_summary = summarize_kubernetes_pods(
                node_pods,
                startup_grace_minutes=startup_grace_minutes,
                max_items=max_evidence,
            )
            status = "fail" if node_summary["failing_pod_count"] else "warn" if node_summary["pending"] else "pass"
            severity = "high" if node_summary["failing_pod_count"] else "medium" if node_summary["pending"] else "low"
            checks.append(
                result(
                    "kubernetes",
                    "Kubernetes pod health",
                    status,
                    severity,
                    f"Kubernetes pod scan found {node_summary['failing_pod_count']} failing pod(s) and {node_summary['pending']} pending pod(s) on node {raw_node}.",
                    with_thresholds(
                        {
                            "node": raw_node,
                            "auth_source": client.source,
                            "startup_grace_minutes": startup_grace_minutes,
                            "inspected_pods": node_summary["inspected_pods"],
                            "pending": node_summary["pending"],
                            "failing_pod_count": node_summary["failing_pod_count"],
                            "phases": node_summary["phases"],
                            "reasons": node_summary["reasons"],
                            "failing_pods": node_summary["failing_pods"],
                        },
                        metric="failing_pod_count",
                        label="Failing pods",
                        unit="",
                        warn=1,
                        fail=1,
                    ),
                )
            )
            if env_bool("ROOTTRACE_KUBERNETES_SYSTEM_POD_CHECKS", True):
                try:
                    system_namespaces = split_csv(env("ROOTTRACE_KUBERNETES_SYSTEM_NAMESPACES", "kube-system"))
                    system_namespace_set = set(system_namespaces)
                    system_pods = [pod for pod in node_pods if pod_metadata(pod)["namespace"] in system_namespace_set]
                    include_unscheduled = env_bool("ROOTTRACE_KUBERNETES_INCLUDE_UNSCHEDULED_SYSTEM_PODS", True)
                    if include_unscheduled:
                        for namespace in system_namespaces:
                            namespace_pods = client.get_json(f"/api/v1/namespaces/{quote(namespace, safe='')}/pods")
                            for pod in namespace_pods.get("items", []) or []:
                                pod_node = pod_metadata(pod).get("node")
                                if not pod_node or pod_node == raw_node:
                                    system_pods.append(pod)
                    system_pods = dedupe_pods(system_pods)
                    system_summary = summarize_kubernetes_pods(
                        system_pods,
                        startup_grace_minutes=startup_grace_minutes,
                        system_pod=True,
                        max_items=max_evidence,
                    )
                    system_status = "fail" if system_summary["failing_pod_count"] else "pass"
                    system_severity = "critical" if system_summary["failing_pod_count"] else "low"
                    namespace_label = ", ".join(system_namespaces)
                    checks.append(
                        result(
                            "kubernetes_system_pods",
                            "Kubernetes system pod startup",
                            system_status,
                            system_severity,
                            f"Kubernetes system namespace scan found {system_summary['failing_pod_count']} failing startup pod(s) across {namespace_label}.",
                            with_thresholds(
                                {
                                    "node": raw_node,
                                    "auth_source": client.source,
                                    "namespaces": system_namespaces,
                                    "startup_grace_minutes": startup_grace_minutes,
                                    "inspected_pods": system_summary["inspected_pods"],
                                    "pending": system_summary["pending"],
                                    "failing_pod_count": system_summary["failing_pod_count"],
                                    "phases": system_summary["phases"],
                                    "reasons": system_summary["reasons"],
                                    "failing_pods": system_summary["failing_pods"],
                                    "includes_unscheduled_system_pods": include_unscheduled,
                                },
                                metric="failing_pod_count",
                                label="Failing pods",
                                unit="",
                                warn=1,
                                fail=1,
                            ),
                        )
                    )
                except urllib.error.HTTPError as exc:
                    checks.append(
                        result(
                            "kubernetes_system_pods",
                            "Kubernetes system pod startup",
                            "unknown",
                            "medium",
                            "Kubernetes API rejected the system namespace pod list request; check RootTrace collector RBAC.",
                            {"status_code": exc.code},
                        )
                    )
                except Exception as exc:
                    checks.append(result("kubernetes_system_pods", "Kubernetes system pod startup", "unknown", "low", "Could not collect Kubernetes system pod startup health.", {"error": str(exc)}))
        except urllib.error.HTTPError as exc:
            checks.append(
                result(
                    "kubernetes",
                    "Kubernetes pod health",
                    "unknown",
                    "medium",
                    "Kubernetes API rejected the pod list request; check RootTrace collector RBAC.",
                    {"status_code": exc.code},
                )
            )
        except Exception as exc:
            checks.append(result("kubernetes", "Kubernetes pod health", "unknown", "low", "Could not collect Kubernetes pod health.", {"error": str(exc)}))
    return checks


def kubernetes_memory_to_bytes(raw: str | None) -> int | None:
    if not raw:
        return None
    match = re.fullmatch(r"([0-9.]+)([KMGTE]i?|[kmgte])?", str(raw))
    if not match:
        return None
    number = float(match.group(1))
    unit = (match.group(2) or "").lower()
    multipliers = {
        "": 1,
        "k": 1000,
        "m": 1000**2,
        "g": 1000**3,
        "t": 1000**4,
        "ki": 1024,
        "mi": 1024**2,
        "gi": 1024**3,
        "ti": 1024**4,
    }
    return int(number * multipliers.get(unit, 1))


def kubernetes_cpu_to_millicores(raw: str | None) -> int | None:
    if not raw:
        return None
    text = str(raw)
    try:
        if text.endswith("m"):
            return int(float(text[:-1]))
        return int(float(text) * 1000)
    except ValueError:
        return None


def check_kubernetes_node() -> list[dict[str, Any]]:
    if not check_enabled("kubernetes_node"):
        return []
    try:
        client = kubernetes_api_client()
    except Exception as exc:
        if not kubernetes_kubeconfig_available() and not explicitly_enabled("kubernetes_node"):
            return []
        return [
            result(
                "kubernetes_node",
                "Kubernetes node conditions",
                "unknown",
                "medium",
                "Could not load Kubernetes API credentials.",
                {"error": str(exc)},
            )
        ]
    if client is None:
        return []
    raw_node = env("ROOTTRACE_HOSTNAME", socket.gethostname())
    try:
        node = client.get_json(f"/api/v1/nodes/{quote(raw_node, safe='')}")
    except urllib.error.HTTPError as exc:
        return [
            result(
                "kubernetes_node",
                "Kubernetes node conditions",
                "unknown",
                "medium",
                "Kubernetes API rejected the node condition request; check RootTrace collector RBAC.",
                {"node": raw_node, "auth_source": client.source, "status_code": exc.code},
            )
        ]
    except Exception as exc:
        return [
            result(
                "kubernetes_node",
                "Kubernetes node conditions",
                "unknown",
                "low",
                "Could not collect Kubernetes node conditions.",
                {"node": raw_node, "auth_source": client.source, "error": str(exc)},
            )
        ]

    status_raw = node.get("status") if isinstance(node, dict) else {}
    spec_raw = node.get("spec") if isinstance(node, dict) else {}
    conditions = status_raw.get("conditions", []) if isinstance(status_raw, dict) else []
    capacity = status_raw.get("capacity", {}) if isinstance(status_raw, dict) else {}
    allocatable = status_raw.get("allocatable", {}) if isinstance(status_raw, dict) else {}
    condition_rows = []
    bad_conditions = []
    ready = "unknown"
    for condition in conditions or []:
        condition_type = condition.get("type") or "Unknown"
        condition_status = str(condition.get("status") or "Unknown")
        is_bad = (condition_type == "Ready" and condition_status != "True") or (
            condition_type != "Ready" and condition_status == "True"
        )
        row = {
            "type": condition_type,
            "status": condition_status,
            "reason": condition.get("reason"),
            "message": condition.get("message"),
            "last_transition_time": condition.get("lastTransitionTime"),
        }
        condition_rows.append(row)
        if condition_type == "Ready":
            ready = condition_status
        if is_bad:
            bad_conditions.append(row)

    warning_events: list[dict[str, Any]] = []
    if env_bool("ROOTTRACE_KUBERNETES_NODE_EVENT_CHECKS", True):
        try:
            events = client.get_json(
                "/api/v1/events",
                {"fieldSelector": f"involvedObject.kind=Node,involvedObject.name={raw_node},type=Warning"},
            )
            event_items = events.get("items", [])[:20] if isinstance(events, dict) else []
            for event in event_items:
                warning_events.append(
                    {
                        "reason": event.get("reason"),
                        "message": event.get("message"),
                        "count": event.get("count"),
                        "last_timestamp": event.get("lastTimestamp") or event.get("eventTime"),
                    }
                )
        except Exception:
            warning_events = []

    bad_count = len(bad_conditions)
    status = "fail" if any(item.get("type") == "Ready" for item in bad_conditions) else "warn" if bad_count or warning_events else "pass"
    severity = "high" if status == "fail" else "medium" if status == "warn" else "low"
    return [
        result(
            "kubernetes_node",
            "Kubernetes node conditions",
            status,
            severity,
            f"Kubernetes node {raw_node} Ready={ready} with {bad_count} pressure/not-ready condition(s).",
            with_thresholds(
                {
                    "node": raw_node,
                    "auth_source": client.source,
                    "unschedulable": bool(spec_raw.get("unschedulable")) if isinstance(spec_raw, dict) else False,
                    "ready": ready,
                    "bad_condition_count": bad_count,
                    "conditions": condition_rows,
                    "bad_conditions": bad_conditions,
                    "warning_event_count": len(warning_events),
                    "warning_events": warning_events,
                    "capacity_cpu_millicores": kubernetes_cpu_to_millicores(capacity.get("cpu")) if isinstance(capacity, dict) else None,
                    "allocatable_cpu_millicores": kubernetes_cpu_to_millicores(allocatable.get("cpu")) if isinstance(allocatable, dict) else None,
                    "capacity_memory_bytes": kubernetes_memory_to_bytes(capacity.get("memory")) if isinstance(capacity, dict) else None,
                    "allocatable_memory_bytes": kubernetes_memory_to_bytes(allocatable.get("memory")) if isinstance(allocatable, dict) else None,
                    "capacity_pods": capacity.get("pods") if isinstance(capacity, dict) else None,
                    "allocatable_pods": allocatable.get("pods") if isinstance(allocatable, dict) else None,
                },
                metric="bad_condition_count",
                label="Bad conditions",
                unit="",
                warn=1,
                fail=1,
            ),
        )
    ]


EKS_ADDON_POD_PREFIXES = (
    "aws-load-balancer-controller",
    "aws-node",
    "aws-ebs-csi",
    "aws-efs-csi",
    "coredns",
    "ebs-csi",
    "efs-csi",
    "external-dns",
    "kube-proxy",
)


def check_eks() -> list[dict[str, Any]]:
    cluster_name = env("ROOTTRACE_EKS_CLUSTER_NAME")
    requested = service_check_requested("eks", "ROOTTRACE_EKS_CLUSTER_NAME")
    if not check_enabled("eks") and not requested:
        return []
    try:
        client = kubernetes_api_client()
    except Exception as exc:
        if not requested and not kubernetes_kubeconfig_available():
            return []
        return [
            result(
                "eks",
                "EKS cluster context",
                "unknown",
                "medium",
                "Could not load Kubernetes API credentials for EKS checks.",
                {"cluster_name": cluster_name or None, "error": str(exc)},
            )
        ]
    if client is None:
        return [] if not requested else [result("eks", "EKS cluster context", "unknown", "low", "Kubernetes API credentials are not configured.", {})]

    checks: list[dict[str, Any]] = []
    is_eks = bool(cluster_name)
    version_payload: dict[str, Any] = {}
    try:
        version_payload = client.get_json("/version")
        git_version = str(version_payload.get("gitVersion") or "")
        is_eks = is_eks or "eks" in git_version.lower()
        if not is_eks and not requested:
            return []
        checks.append(
            result(
                "eks",
                "EKS Kubernetes API version",
                "pass" if is_eks else "unknown",
                "low" if is_eks else "medium",
                "Kubernetes API version indicates an EKS cluster." if is_eks else "Kubernetes API is reachable, but EKS could not be confirmed.",
                {
                    "cluster_name": cluster_name or None,
                    "auth_source": client.source,
                    "git_version": version_payload.get("gitVersion"),
                    "major": version_payload.get("major"),
                    "minor": version_payload.get("minor"),
                    "eks_detected": is_eks,
                    "detection_method": "gitVersion" if "eks" in git_version.lower() else "configured_cluster_name" if cluster_name else "unknown",
                },
            )
        )
    except Exception as exc:
        if not requested:
            return []
        checks.append(
            result(
                "eks",
                "EKS Kubernetes API version",
                "unknown",
                "medium",
                "Could not read Kubernetes API version for EKS detection.",
                {"cluster_name": cluster_name or None, "auth_source": client.source, "error": str(exc)},
            )
        )

    if env_bool("ROOTTRACE_EKS_ADDON_POD_CHECKS", True):
        try:
            pods_payload = client.get_json("/api/v1/namespaces/kube-system/pods")
            raw_pods = list(pods_payload.get("items", []) or [])
            prefixes = tuple(split_csv(env("ROOTTRACE_EKS_ADDON_PREFIXES")) or EKS_ADDON_POD_PREFIXES)
            addon_pods = [
                pod
                for pod in raw_pods
                if any(pod_metadata(pod)["name"].startswith(prefix) for prefix in prefixes)
            ]
            summary = summarize_kubernetes_pods(
                addon_pods,
                startup_grace_minutes=env_float("ROOTTRACE_KUBERNETES_STARTUP_GRACE_MINUTES", 10.0),
                system_pod=True,
                max_items=env_int("ROOTTRACE_KUBERNETES_MAX_POD_EVIDENCE", 20),
            )
            status = "fail" if summary["failing_pod_count"] else "pass"
            checks.append(
                result(
                    "eks",
                    "EKS add-on pod health",
                    status,
                    "critical" if status == "fail" else "low",
                    f"EKS add-on scan found {summary['failing_pod_count']} failing pod(s) in kube-system.",
                    with_thresholds(
                        {
                            "cluster_name": cluster_name or None,
                            "auth_source": client.source,
                            "inspected_pods": summary["inspected_pods"],
                            "pending": summary["pending"],
                            "failing_pod_count": summary["failing_pod_count"],
                            "addon_prefixes": list(prefixes),
                            "phases": summary["phases"],
                            "reasons": summary["reasons"],
                            "failing_pods": summary["failing_pods"],
                        },
                        metric="failing_pod_count",
                        label="Failing pods",
                        unit="",
                        warn=1,
                        fail=1,
                    ),
                )
            )
        except urllib.error.HTTPError as exc:
            checks.append(
                result(
                    "eks",
                    "EKS add-on pod health",
                    "unknown",
                    "medium",
                    "Kubernetes API rejected the EKS add-on pod list request; check collector RBAC.",
                    {"cluster_name": cluster_name or None, "auth_source": client.source, "status_code": exc.code},
                )
            )
        except Exception as exc:
            checks.append(
                result(
                    "eks",
                    "EKS add-on pod health",
                    "unknown",
                    "low",
                    "Could not collect EKS add-on pod health.",
                    {"cluster_name": cluster_name or None, "auth_source": client.source, "error": str(exc)},
                )
            )
    return checks


def load_json_config(path: str) -> tuple[Any, str | None]:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8")), None
    except (OSError, json.JSONDecodeError) as exc:
        return None, str(exc)


def synthetic_substitute(text: str, variables: dict[str, Any]) -> str:
    for key, value in variables.items():
        text = text.replace("{" + key + "}", str(value))
    return text


def synthetic_json_path(payload: Any, path: str) -> Any:
    current = payload
    for part in str(path).split("."):
        if isinstance(current, dict):
            if part not in current:
                return None
            current = current[part]
        elif isinstance(current, list) and part.lstrip("-").isdigit():
            index = int(part)
            if not -len(current) <= index < len(current):
                return None
            current = current[index]
        else:
            return None
    return current


def run_synthetic_step(step: dict[str, Any], variables: dict[str, Any], timeout: float) -> tuple[dict[str, Any], list[str]]:
    method = str(step.get("method") or "GET").upper()
    url = synthetic_substitute(str(step.get("url") or ""), variables)
    headers = {str(key): synthetic_substitute(str(value), variables) for key, value in (step.get("headers") or {}).items()}
    body = step.get("body")
    if isinstance(body, (dict, list)):
        body = json.dumps(body)
        headers.setdefault("Content-Type", "application/json")
    data = synthetic_substitute(body, variables).encode("utf-8") if isinstance(body, str) else None
    started = time.monotonic()
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            code = response.status
            text = response.read(1_048_576).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        code = exc.code
        text = exc.read(1_048_576).decode("utf-8", errors="replace")
    elapsed_ms = round((time.monotonic() - started) * 1000, 2)

    failures: list[str] = []
    assertions = step.get("assert") or {}
    expected_statuses = assertions.get("status")
    if isinstance(expected_statuses, list):
        allowed = {int(item) for item in expected_statuses if str(item).isdigit()}
        if allowed and code not in allowed:
            failures.append(f"status {code} not in {sorted(allowed)}")
    elif code >= 400:
        failures.append(f"status {code}")
    body_contains = assertions.get("body_contains")
    if body_contains and str(body_contains) not in text:
        failures.append(f"body does not contain {str(body_contains)[:120]!r}")
    max_latency_ms = assertions.get("max_latency_ms")
    if isinstance(max_latency_ms, (int, float)) and elapsed_ms > max_latency_ms:
        failures.append(f"latency {elapsed_ms} ms exceeded {max_latency_ms} ms")

    for var, spec in (step.get("extract") or {}).items():
        value = None
        if isinstance(spec, dict) and "json" in spec:
            try:
                value = synthetic_json_path(json.loads(text), spec["json"])
            except json.JSONDecodeError:
                value = None
        elif isinstance(spec, dict) and "regex" in spec:
            match = re.search(str(spec["regex"]), text)
            if match:
                value = match.group(1) if match.groups() else match.group(0)
        if value is None:
            failures.append(f"could not extract variable {var}")
        else:
            variables[str(var)] = value

    evidence = {
        "step": str(step.get("name") or url),
        "method": method,
        "url": redact_url_credentials(url),
        "http_status": code,
        "latency_ms": elapsed_ms,
        "failures": failures,
    }
    return evidence, failures


def check_synthetic_journeys() -> list[dict[str, Any]]:
    path = env("ROOTTRACE_SYNTHETIC_JOURNEYS_PATH")
    if not path:
        return []
    journeys, load_error = load_json_config(path)
    if load_error or not isinstance(journeys, list):
        return [
            result(
                "synthetic",
                "Synthetic journey config",
                "unknown",
                "low",
                f"Could not load synthetic journeys from {path}.",
                {"path": path, "error": load_error or "expected a JSON list of journeys"},
            )
        ]
    timeout = env_float("ROOTTRACE_SYNTHETIC_TIMEOUT_SECONDS", CHECK_TIMEOUT_SECONDS)
    warn_ms = env_float("ROOTTRACE_SYNTHETIC_LATENCY_WARN_MS", 2000.0)
    fail_ms = env_float("ROOTTRACE_SYNTHETIC_LATENCY_FAIL_MS", 5000.0)
    checks: list[dict[str, Any]] = []
    for journey in journeys:
        if not isinstance(journey, dict):
            continue
        name = str(journey.get("name") or "journey")
        variables: dict[str, Any] = {}
        step_evidence: list[dict[str, Any]] = []
        failing_step: str | None = None
        failure_detail: str | None = None
        started = time.monotonic()
        for step in journey.get("steps") or []:
            if not isinstance(step, dict):
                continue
            step_name = str(step.get("name") or step.get("url") or "step")
            try:
                evidence, failures = run_synthetic_step(step, variables, timeout)
                step_evidence.append(evidence)
                if failures:
                    failing_step = step_name
                    failure_detail = "; ".join(failures)
                    break
            except Exception as exc:
                step_evidence.append({"step": step_name, "error": str(exc)})
                failing_step = step_name
                failure_detail = str(exc)
                break
        total_ms = round((time.monotonic() - started) * 1000, 2)
        if failing_step:
            status, severity = "fail", "high"
            message = f"Synthetic journey {name} failed at step {failing_step}: {failure_detail}"
        else:
            status, severity = threshold_status(total_ms, warn_ms, fail_ms)
            message = f"Synthetic journey {name} completed {len(step_evidence)} step(s) in {total_ms} ms."
        checks.append(
            result(
                "synthetic",
                f"Synthetic journey {name}",
                status,
                severity,
                message,
                with_thresholds(
                    {
                        "journey": name,
                        "latency_ms": total_ms,
                        "step_count": len(step_evidence),
                        "failing_step": failing_step,
                        "steps": step_evidence[:32],
                    },
                    metric="latency_ms",
                    label="Journey latency",
                    unit="ms",
                    warn=warn_ms,
                    fail=fail_ms,
                ),
            )
        )
    return checks


def check_browser_journeys() -> list[dict[str, Any]]:
    path = env("ROOTTRACE_BROWSER_JOURNEYS_PATH")
    if not path:
        return []
    try:
        from playwright.sync_api import sync_playwright  # type: ignore[import-not-found]
    except ImportError:
        return [
            result(
                "browser",
                "Browser journeys",
                "unknown",
                "low",
                "Browser journeys are configured but playwright is not installed.",
                {"path": path, "error": "playwright.sync_api is not importable; pip install playwright && playwright install chromium"},
            )
        ]
    journeys, load_error = load_json_config(path)
    if load_error or not isinstance(journeys, list):
        return [
            result(
                "browser",
                "Browser journey config",
                "unknown",
                "low",
                f"Could not load browser journeys from {path}.",
                {"path": path, "error": load_error or "expected a JSON list of journeys"},
            )
        ]
    default_timeout_ms = env_int("ROOTTRACE_BROWSER_STEP_TIMEOUT_MS", 10_000)
    warn_ms = env_float("ROOTTRACE_BROWSER_LATENCY_WARN_MS", 10_000.0)
    fail_ms = env_float("ROOTTRACE_BROWSER_LATENCY_FAIL_MS", 30_000.0)
    checks: list[dict[str, Any]] = []
    for journey in journeys:
        if not isinstance(journey, dict):
            continue
        name = str(journey.get("name") or "journey")
        step_evidence: list[dict[str, Any]] = []
        failing_step: str | None = None
        failure_detail: str | None = None
        started = time.monotonic()
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                try:
                    page = browser.new_page()
                    page.goto(str(journey.get("start_url") or ""), timeout=default_timeout_ms)
                    for step in journey.get("steps") or []:
                        if not isinstance(step, dict):
                            continue
                        action = str(step.get("action") or "")
                        selector = str(step.get("selector") or "")
                        timeout_ms = int(step.get("timeout_ms") or default_timeout_ms)
                        step_name = f"{action} {selector}".strip()
                        step_started = time.monotonic()
                        try:
                            if action == "goto":
                                page.goto(str(step.get("value") or ""), timeout=timeout_ms)
                            elif action == "click":
                                page.click(selector, timeout=timeout_ms)
                            elif action == "fill":
                                page.fill(selector, str(step.get("value") or ""), timeout=timeout_ms)
                            elif action == "wait_for":
                                page.wait_for_selector(selector, timeout=timeout_ms)
                            elif action == "assert_text":
                                content = page.text_content(selector, timeout=timeout_ms) if selector else page.content()
                                expected = str(step.get("text") or "")
                                if expected not in (content or ""):
                                    raise RuntimeError(f"expected text {expected[:120]!r} not found")
                            else:
                                raise RuntimeError(f"unsupported action {action!r}")
                            step_evidence.append({"step": step_name, "latency_ms": round((time.monotonic() - step_started) * 1000, 2)})
                        except Exception as exc:
                            step_evidence.append({"step": step_name, "error": str(exc)[:500]})
                            failing_step = step_name
                            failure_detail = str(exc)
                            break
                finally:
                    browser.close()
        except Exception as exc:
            failing_step = failing_step or "launch"
            failure_detail = failure_detail or str(exc)
        duration_ms = round((time.monotonic() - started) * 1000, 2)
        if failing_step:
            status, severity = "fail", "high"
            message = f"Browser journey {name} failed at step {failing_step}: {str(failure_detail)[:300]}"
        else:
            status, severity = threshold_status(duration_ms, warn_ms, fail_ms)
            message = f"Browser journey {name} completed {len(step_evidence)} step(s) in {duration_ms} ms."
        checks.append(
            result(
                "browser",
                f"Browser journey {name}",
                status,
                severity,
                message,
                with_thresholds(
                    {
                        "journey": name,
                        "start_url": redact_url_credentials(str(journey.get("start_url") or "")),
                        "duration_ms": duration_ms,
                        "step_count": len(step_evidence),
                        "failing_step": failing_step,
                        "steps": step_evidence[:32],
                    },
                    metric="duration_ms",
                    label="Journey duration",
                    unit="ms",
                    warn=warn_ms,
                    fail=fail_ms,
                ),
            )
        )
    return checks


def check_dns_targets() -> list[dict[str, Any]]:
    targets = split_csv(env("ROOTTRACE_DNS_TARGETS"))
    if not targets:
        return []
    warn_ms = env_float("ROOTTRACE_DNS_WARN_MS", 200.0)
    fail_ms = env_float("ROOTTRACE_DNS_FAIL_MS", 1000.0)
    checks: list[dict[str, Any]] = []
    for hostname in targets:
        started = time.monotonic()
        try:
            infos = socket.getaddrinfo(hostname, None)
        except OSError as exc:
            checks.append(
                result(
                    "dns",
                    f"DNS resolution {hostname}",
                    "fail",
                    "high",
                    f"DNS resolution failed for {hostname}.",
                    {"hostname": hostname, "error": str(exc)},
                )
            )
            continue
        elapsed_ms = round((time.monotonic() - started) * 1000, 2)
        addresses = sorted({info[4][0] for info in infos if info and info[4]})
        status, severity = threshold_status(elapsed_ms, warn_ms, fail_ms)
        checks.append(
            result(
                "dns",
                f"DNS resolution {hostname}",
                status,
                severity,
                f"{hostname} resolved to {len(addresses)} address(es) in {elapsed_ms} ms.",
                with_thresholds(
                    {
                        "hostname": hostname,
                        "latency_ms": elapsed_ms,
                        "address_count": len(addresses),
                        "addresses": addresses[:16],
                    },
                    metric="latency_ms",
                    label="DNS latency",
                    unit="ms",
                    warn=warn_ms,
                    fail=fail_ms,
                ),
            )
        )
    return checks


def check_ping_targets() -> list[dict[str, Any]]:
    targets = split_csv(env("ROOTTRACE_PING_TARGETS"))
    if not targets:
        return []
    ping_binary = shutil.which("ping")
    if not ping_binary:
        return [
            result(
                "ping",
                "Ping checks",
                "unknown",
                "low",
                "Ping targets are configured but no ping binary is available.",
                {"targets": targets[:16], "error": "ping binary not found in PATH"},
            )
        ]
    warn_ms = env_float("ROOTTRACE_PING_WARN_MS", 100.0)
    fail_ms = env_float("ROOTTRACE_PING_FAIL_MS", 500.0)
    wait_args = ["-W", "2000"] if platform.system() == "Darwin" else ["-W", "2"]
    checks: list[dict[str, Any]] = []
    for target in targets:
        try:
            proc = subprocess.run(
                [ping_binary, "-c", "1", *wait_args, target],
                capture_output=True,
                text=True,
                timeout=env_float("ROOTTRACE_PING_TIMEOUT_SECONDS", 5.0),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            checks.append(result("ping", f"Ping {target}", "fail", "high", f"Ping failed for {target}.", {"target": target, "error": str(exc)}))
            continue
        rtt_match = re.search(r"time[=<]([\d.]+)\s*ms", proc.stdout)
        if proc.returncode != 0 or not rtt_match:
            checks.append(
                result(
                    "ping",
                    f"Ping {target}",
                    "fail",
                    "high",
                    f"{target} did not answer ICMP echo.",
                    {"target": target, "exit_code": proc.returncode, "output": (proc.stdout or proc.stderr)[:500]},
                )
            )
            continue
        rtt_ms = round(float(rtt_match.group(1)), 2)
        status, severity = threshold_status(rtt_ms, warn_ms, fail_ms)
        checks.append(
            result(
                "ping",
                f"Ping {target}",
                status,
                severity,
                f"{target} answered ICMP echo in {rtt_ms} ms.",
                with_thresholds(
                    {"target": target, "rtt_ms": rtt_ms},
                    metric="rtt_ms",
                    label="Round-trip time",
                    unit="ms",
                    warn=warn_ms,
                    fail=fail_ms,
                ),
            )
        )
    return checks


def check_status_pages() -> list[dict[str, Any]]:
    targets = split_csv(env("ROOTTRACE_STATUS_PAGES"))
    if not targets:
        return []
    timeout = env_float("ROOTTRACE_STATUS_PAGE_TIMEOUT_SECONDS", CHECK_TIMEOUT_SECONDS)
    checks: list[dict[str, Any]] = []
    for raw in targets:
        name, url = parse_http_target(raw)
        safe_url = redact_url_credentials(url)
        try:
            started = time.monotonic()
            code, text = http_text_status(url, timeout=timeout)
            elapsed_ms = round((time.monotonic() - started) * 1000, 2)
        except Exception as exc:
            checks.append(
                result(
                    "status_page",
                    f"{name} status page",
                    "fail",
                    "high",
                    f"{name} status page check failed.",
                    {"target": name, "url": safe_url, "error": str(exc)},
                )
            )
            continue
        indicator = None
        description = None
        try:
            payload = json.loads(text)
            status_block = payload.get("status") if isinstance(payload, dict) else None
            if isinstance(status_block, dict):
                indicator = str(status_block.get("indicator") or "").lower() or None
                description = str(status_block.get("description") or "") or None
        except json.JSONDecodeError:
            pass
        if indicator is not None:
            if indicator in {"none", "operational"}:
                status, severity = "pass", "low"
            elif indicator == "minor":
                status, severity = "warn", "medium"
            elif indicator in {"major", "critical"}:
                status, severity = "fail", "high"
            else:
                status, severity = "warn", "medium"
            message = f"{name} reports status indicator {indicator}."
        elif code == 200:
            status, severity = "pass", "low"
            message = f"{name} status page returned HTTP 200."
        else:
            status, severity = "fail", "high"
            message = f"{name} status page returned HTTP {code}."
        checks.append(
            result(
                "status_page",
                f"{name} status page",
                status,
                severity,
                message,
                {
                    "target": name,
                    "url": safe_url,
                    "http_status": code,
                    "latency_ms": elapsed_ms,
                    "indicator": indicator,
                    "description": description,
                },
            )
        )
    return checks


def certificate_not_after(cert_path: str) -> tuple[datetime | None, str]:
    raw = Path(cert_path).read_bytes()
    try:
        from cryptography import x509  # type: ignore[import-not-found]

        try:
            cert = x509.load_pem_x509_certificate(raw)
        except ValueError:
            cert = x509.load_der_x509_certificate(raw)
        not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
        return not_after, "cryptography"
    except ImportError:
        pass
    openssl = shutil.which("openssl")
    if not openssl:
        return None, "unavailable"
    for inform in ("PEM", "DER"):
        proc = subprocess.run(
            [openssl, "x509", "-enddate", "-noout", "-inform", inform, "-in", cert_path],
            capture_output=True,
            text=True,
            timeout=CHECK_TIMEOUT_SECONDS,
        )
        if proc.returncode != 0:
            continue
        match = re.search(r"notAfter=(.+)", proc.stdout)
        if match:
            parsed = datetime.strptime(match.group(1).strip(), "%b %d %H:%M:%S %Y %Z")
            return parsed.replace(tzinfo=timezone.utc), "openssl"
    return None, "openssl"


def check_secret_expiry() -> list[dict[str, Any]]:
    path = env("ROOTTRACE_SECRET_EXPIRY_PATH")
    if not path:
        return []
    entries, load_error = load_json_config(path)
    if load_error or not isinstance(entries, list):
        return [
            result(
                "secret_expiry",
                "Secret expiry config",
                "unknown",
                "low",
                f"Could not load secret expiry config from {path}.",
                {"path": path, "error": load_error or "expected a JSON list of entries"},
            )
        ]
    checks: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or entry.get("cert_file") or "secret")
        warn_days = env_float("ROOTTRACE_SECRET_EXPIRY_WARN_DAYS", 30.0) if entry.get("warn_days") is None else float(entry["warn_days"])
        fail_days = env_float("ROOTTRACE_SECRET_EXPIRY_FAIL_DAYS", 7.0) if entry.get("fail_days") is None else float(entry["fail_days"])
        expires_at: datetime | None = None
        expiry_source = "config"
        error: str | None = None
        if entry.get("expires_at"):
            try:
                expires_at = datetime.fromisoformat(str(entry["expires_at"]).replace("Z", "+00:00"))
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)
            except ValueError as exc:
                error = str(exc)
        elif entry.get("cert_file"):
            try:
                expires_at, expiry_source = certificate_not_after(str(entry["cert_file"]))
                if expires_at is None:
                    error = "neither the cryptography package nor an openssl binary could read the certificate"
            except Exception as exc:
                error = str(exc)
        else:
            error = "entry has neither expires_at nor cert_file"
        if expires_at is None:
            checks.append(
                result(
                    "secret_expiry",
                    f"{name} expiry",
                    "unknown",
                    "medium",
                    f"Could not determine expiry for {name}.",
                    {"entry_name": name, "cert_file": entry.get("cert_file"), "error": error},
                )
            )
            continue
        days_remaining = round((expires_at - datetime.now(timezone.utc)).total_seconds() / 86400, 2)
        if days_remaining <= fail_days:
            status, severity = "fail", "critical"
        elif days_remaining <= warn_days:
            status, severity = "warn", "medium"
        else:
            status, severity = "pass", "low"
        checks.append(
            result(
                "secret_expiry",
                f"{name} expiry",
                status,
                severity,
                f"{name} expires in {days_remaining} day(s).",
                with_thresholds(
                    {
                        "entry_name": name,
                        "expires_at": expires_at.isoformat(),
                        "days_remaining": days_remaining,
                        "expiry_source": expiry_source,
                        "cert_file": entry.get("cert_file"),
                    },
                    metric="days_remaining",
                    label="Days remaining",
                    unit="d",
                    warn=warn_days,
                    fail=fail_days,
                    higher_is_worse=False,
                ),
            )
        )
    return checks


def check_systemd_timers() -> list[dict[str, Any]]:
    if not env_bool("ROOTTRACE_SYSTEMD_TIMER_CHECK", False):
        return []
    bus, manager, manager_error = _systemd_dbus_manager()
    if manager_error:
        return [
            result(
                "systemd_timer",
                "systemd timers",
                "unknown",
                "low",
                "Could not inspect systemd timers.",
                with_thresholds(
                    {"error": manager_error, "failed_timer_count": 0, "source": "systemd_dbus"},
                    metric="failed_timer_count",
                    label="Failed timers",
                    unit="",
                    warn=1,
                    fail=1,
                ),
            )
        ]
    try:
        units = {
            _decode_systemd_value(row[0]): (_decode_systemd_value(row[3]), _decode_systemd_value(row[4]))
            for row in manager.ListUnits()
            if len(row) > 4
        }
    except Exception as exc:  # pragma: no cover - depends on host D-Bus/systemd.
        return [
            result(
                "systemd_timer",
                "systemd timers",
                "unknown",
                "low",
                "Could not inspect systemd timers.",
                with_thresholds(
                    {"error": str(exc), "failed_timer_count": 0, "source": "systemd_dbus"},
                    metric="failed_timer_count",
                    label="Failed timers",
                    unit="",
                    warn=1,
                    fail=1,
                ),
            )
        ]
    timers = {name: states for name, states in units.items() if name.endswith(".timer")}
    problems: list[dict[str, Any]] = []
    for timer_name in sorted(timers):
        active_state, sub_state = timers[timer_name]
        service_name = timer_name[: -len(".timer")] + ".service"
        service_active_state = units.get(service_name, ("", ""))[0]
        issues: list[str] = []
        if active_state != "active":
            issues.append(f"timer is {active_state}")
        if service_active_state == "failed":
            issues.append("last service run failed")
        if issues:
            problems.append(
                {
                    "timer": timer_name,
                    "active_state": active_state,
                    "sub_state": sub_state,
                    "service": service_name,
                    "service_active_state": service_active_state or None,
                    "issues": issues,
                }
            )
    failed_count = len(problems)
    if failed_count:
        message = f"{failed_count} of {len(timers)} systemd timer(s) are inactive, failed, or backed by a failed service."
    else:
        message = f"All {len(timers)} systemd timer(s) are active and their services are healthy."
    checks_result = result(
        "systemd_timer",
        "systemd timers",
        "fail" if failed_count else "pass",
        "high" if failed_count else "low",
        message,
        with_thresholds(
            {
                "timer_count": len(timers),
                "failed_timer_count": failed_count,
                "problem_timers": problems[:50],
                "source": "systemd_dbus",
            },
            metric="failed_timer_count",
            label="Failed timers",
            unit="",
            warn=1,
            fail=1,
        ),
    )
    return [checks_result]


def log_ship_targets() -> list[tuple[str, Path]]:
    targets: list[tuple[str, Path]] = []
    for item in split_csv(env("ROOTTRACE_LOG_FILES")):
        if "=" not in item:
            continue
        service, path = item.split("=", 1)
        service = service.strip()
        path = path.strip()
        if service and path:
            targets.append((service, Path(path)))
    return targets


def log_ship_state_path() -> Path:
    configured = env("ROOTTRACE_LOG_SHIP_STATE_PATH")
    if configured:
        return Path(configured)
    state_dir = Path(env("ROOTTRACE_STATE_DIR", "/var/lib/roottrace-collector"))
    return state_dir / "log_ship_offsets.json"


def load_log_ship_state() -> dict[str, Any]:
    path = log_ship_state_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"version": 1, "files": {}}
    if not isinstance(data, dict):
        return {"version": 1, "files": {}}
    if not isinstance(data.get("files"), dict):
        data["files"] = {}
    return data


def save_log_ship_state(state: dict[str, Any]) -> None:
    path = log_ship_state_path()
    try:
        path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
        tmp = path.with_suffix(f".{os.getpid()}.tmp")
        tmp.write_text(json.dumps(state, separators=(",", ":")), encoding="utf-8")
        tmp.chmod(0o600)
        os.replace(tmp, path)
    except OSError as exc:
        LAST_LOG_SHIP_STATS["state_error"] = str(exc)


def guess_log_level(line: str) -> str:
    match = LOG_LEVEL_MARKER_RE.search(line)
    if not match:
        return "info"
    marker = match.group(1).lower()
    if marker in {"fatal", "critical", "error", "err"}:
        return "error"
    if marker in {"warning", "warn"}:
        return "warn"
    if marker in {"debug", "trace"}:
        return "debug"
    return "info"


def log_entry_from_line(service: str, line: str, hostname: str) -> dict[str, Any]:
    max_message_bytes = 8192
    entry: dict[str, Any] = {"service": service, "host": hostname}
    record = None
    if line.startswith("{"):
        try:
            parsed = json.loads(line)
            if isinstance(parsed, dict):
                record = parsed
        except json.JSONDecodeError:
            record = None
    if record is not None:
        message = record.get("message") or record.get("msg") or line
        level = str(record.get("level") or record.get("severity") or "").lower()
        timestamp = record.get("timestamp") or record.get("time") or record.get("ts")
        logger = record.get("logger")
        attrs = {
            key: value
            for key, value in record.items()
            if key not in {"message", "msg", "level", "severity", "timestamp", "time", "ts", "logger"}
        }
        entry["level"] = level if level in {"debug", "info", "warn", "error"} else guess_log_level(f"{level} {message}")
        if logger:
            entry["logger"] = str(logger)[:256]
        if timestamp is not None:
            entry["timestamp"] = str(timestamp)[:64]
        if attrs:
            entry["attrs"] = dict(list(attrs.items())[:16])
    else:
        message = line
        entry["level"] = guess_log_level(line)
    entry["message"] = str(redact(str(message)))[:max_message_bytes]
    return entry


def read_log_ship_lines(state: dict[str, Any]) -> list[dict[str, Any]]:
    files_state = state.setdefault("files", {})
    if not isinstance(files_state, dict):
        files_state = {}
        state["files"] = files_state
    max_bytes = max(env_int("ROOTTRACE_LOG_SHIP_MAX_BYTES_PER_CYCLE", 2 * 1024 * 1024), 64 * 1024)
    max_lines = max(env_int("ROOTTRACE_LOG_SHIP_MAX_LINES_PER_CYCLE", 2000), 100)
    max_line_bytes = max(env_int("ROOTTRACE_LOG_SHIP_MAX_LINE_BYTES", 64 * 1024), 4096)
    bytes_read = 0
    line_count = 0
    errors: list[str] = []
    batches: list[dict[str, Any]] = []

    for service, path in log_ship_targets():
        path_key = str(path)
        try:
            stat_result = path.stat()
        except OSError as exc:
            errors.append(f"{path_key}: {exc}")
            continue
        previous = files_state.get(path_key) if isinstance(files_state.get(path_key), dict) else None
        same_file = bool(previous) and previous.get("inode") == stat_result.st_ino and previous.get("device") == stat_result.st_dev
        previous_offset = int(previous.get("offset") or 0) if previous else 0
        if same_file and 0 <= previous_offset <= stat_result.st_size:
            offset = previous_offset
        elif previous:
            offset = 0  # file rotated; the replacement is all new content
        elif env_bool("ROOTTRACE_LOG_SHIP_READ_FROM_BEGINNING", False):
            offset = 0
        else:
            offset = stat_result.st_size
        lines: list[tuple[str, int]] = []
        try:
            with path.open("rb") as handle:
                handle.seek(offset)
                while bytes_read < max_bytes and line_count < max_lines:
                    raw = handle.readline(max_line_bytes + 1)
                    if not raw:
                        break
                    if not raw.endswith(b"\n") and len(raw) <= max_line_bytes:
                        break  # partial line still being written; retry next cycle
                    bytes_read += len(raw)
                    line_count += 1
                    if len(raw) > max_line_bytes:
                        continue
                    line = raw.decode("utf-8", errors="replace").strip()
                    if line:
                        lines.append((line, handle.tell()))
        except OSError as exc:
            errors.append(f"{path_key}: {exc}")
            continue
        batches.append(
            {
                "service": service,
                "path": path_key,
                "device": stat_result.st_dev,
                "inode": stat_result.st_ino,
                "size": stat_result.st_size,
                "start_offset": offset,
                "lines": lines,
            }
        )
    LAST_LOG_SHIP_STATS.update(
        {
            "lines_read": line_count,
            "bytes_read": bytes_read,
            "read_errors": errors[:8],
            "last_read_at": utc_now(),
        }
    )
    return batches


def send_log_shipping(client: RootTraceClient, host: dict[str, Any]) -> None:
    if not log_ship_targets():
        return
    hostname = str(host.get("hostname") or socket.gethostname())
    batch_entries = min(max(env_int("ROOTTRACE_LOG_SHIP_BATCH_ENTRIES", 500), 1), 500)
    state = load_log_ship_state()
    files_state = state["files"]
    entries_sent = 0
    send_errors: list[str] = []
    for file_batch in read_log_ship_lines(state):
        shipped_offset = file_batch["start_offset"]
        pairs = [(log_entry_from_line(file_batch["service"], line, hostname), end_offset) for line, end_offset in file_batch["lines"]]
        for index in range(0, len(pairs), batch_entries):
            chunk = pairs[index: index + batch_entries]
            try:
                client.post("logs/ingest", {"entries": [entry for entry, _ in chunk]})
            except Exception as exc:
                send_errors.append(f"{file_batch['path']}: {exc}")
                print(f"{utc_now()} log shipping failed for {file_batch['path']}: {exc}", file=sys.stderr, flush=True)
                break  # keep the offset before this chunk so the lines are retried
            shipped_offset = chunk[-1][1]
            entries_sent += len(chunk)
        files_state[file_batch["path"]] = {
            "device": file_batch["device"],
            "inode": file_batch["inode"],
            "offset": shipped_offset,
            "size": file_batch["size"],
            "updated_at": utc_now(),
        }
    save_log_ship_state(state)
    LAST_LOG_SHIP_STATS.update(
        {
            "entries_sent": entries_sent,
            "send_errors": send_errors[:8],
            "last_sent_at": utc_now(),
        }
    )


def check_collector_self() -> list[dict[str, Any]]:
    durations = {key: round(value, 2) for key, value in LAST_CHECK_DURATIONS_MS.items() if key != "collector_self"}
    max_duration = max(durations.values()) if durations else 0.0
    warn_ms = env_float("ROOTTRACE_COLLECTOR_CHECK_WARN_MS", 10_000.0)
    fail_ms = env_float("ROOTTRACE_COLLECTOR_CHECK_FAIL_MS", 30_000.0)
    status, severity = threshold_status(max_duration, warn_ms, fail_ms)
    enabled = {item.lower() for item in split_csv(env("ROOTTRACE_ENABLED_CHECKS"))}
    disabled = {item.lower() for item in split_csv(env("ROOTTRACE_DISABLED_CHECKS"))}
    configured_checks = [name for name, _ in CHECKERS if name != "collector_self" and (not enabled or name in enabled)]
    skipped_checks = [name for name in configured_checks if name in disabled]
    return [
        result(
            "collector_self",
            "Collector self-health",
            status,
            severity,
            f"Collector completed {len(durations)} check group(s); slowest group took {max_duration} ms.",
            with_thresholds(
                {
                    "collector_version": VERSION,
                    "check_duration_ms": durations,
                    "slowest_check_duration_ms": max_duration,
                    "enabled_check_count": len(configured_checks),
                    "skipped_check_count": len(skipped_checks),
                    "skipped_checks": skipped_checks,
                    "python_version": platform.python_version(),
                    "platform": platform.platform(),
                    "connection_model": "short_lived",
                },
                metric="slowest_check_duration_ms",
                label="Slowest check",
                unit="ms",
                warn=warn_ms,
                fail=fail_ms,
            ),
        )
    ]


CHECKERS: tuple[tuple[str, Callable[[], list[dict[str, Any]]]], ...] = (
    ("disk", check_disk),
    ("inode", check_inode_usage),
    ("disk_io", check_disk_io),
    ("swap", check_swap),
    ("memory", check_memory),
    ("cpu", check_cpu_usage),
    ("network", check_network_health),
    ("tcp", check_tcp_services),
    ("process", check_processes),
    ("systemd", check_systemd_units),
    ("kernel", check_kernel_events),
    ("linux_audit", check_linux_audit),
    ("ec2", check_ec2_metadata),
    ("docker", check_docker),
    ("kubernetes", check_kubernetes),
    ("kubernetes_node", check_kubernetes_node),
    ("eks", check_eks),
    ("http", check_http_endpoints),
    ("tls", check_tls_certificates),
    ("synthetic", check_synthetic_journeys),
    ("browser", check_browser_journeys),
    ("dns", check_dns_targets),
    ("ping", check_ping_targets),
    ("status_page", check_status_pages),
    ("secret_expiry", check_secret_expiry),
    ("systemd_timer", check_systemd_timers),
    ("nginx", check_nginx),
    ("apache", check_apache),
    ("haproxy", check_haproxy),
    ("mongodb", check_mongodb),
    ("postgres", check_postgres),
    ("mysql", check_mysql),
    ("redis", check_redis),
    ("rabbitmq", check_rabbitmq),
    ("elasticsearch", check_elasticsearch),
    ("clickhouse", check_clickhouse),
    ("cassandra", check_cassandra),
    ("nvidia", check_nvidia),
    ("custom", check_custom_metrics),
    ("collector_self", check_collector_self),
)


def run_checker(name: str, checker: Callable[[], list[dict[str, Any]]]) -> list[dict[str, Any]]:
    started = time.monotonic()
    try:
        results = checker()
        LAST_CHECK_DURATIONS_MS[name] = round((time.monotonic() - started) * 1000, 2)
        return results
    except Exception as exc:
        LAST_CHECK_DURATIONS_MS[name] = round((time.monotonic() - started) * 1000, 2)
        return [
            result(
                name,
                f"{name} collector check",
                "unknown",
                "low",
                f"{name} collector check failed before producing results.",
                {"error": str(exc)},
            )
        ]


def iter_check_batches() -> Iterator[tuple[str, list[dict[str, Any]]]]:
    enabled = {item.lower() for item in split_csv(env("ROOTTRACE_ENABLED_CHECKS"))}
    disabled = {item.lower() for item in split_csv(env("ROOTTRACE_DISABLED_CHECKS"))}
    for name, checker in CHECKERS:
        if enabled and name not in enabled:
            continue
        if name in disabled:
            continue
        checks = run_checker(name, checker)
        if checks:
            yield name, checks


def collect_results() -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for _, batch in iter_check_batches():
        checks.extend(batch)
    return checks


def observed_services(results: list[dict[str, Any]]) -> list[str]:
    services = set(split_csv(env("ROOTTRACE_OBSERVED_SERVICES")))
    for item in results:
        service = item.get("service") if isinstance(item, dict) else None
        if service:
            services.add(str(service))
    for raw in split_csv(env("ROOTTRACE_CHECK_PORTS")):
        spec = tcp_check_spec(raw)
        if spec:
            services.add(spec[0])
    if kubernetes_file_checks_enabled() and (env("KUBERNETES_SERVICE_HOST") or kubernetes_kubeconfig_available()):
        services.add("kubernetes")
    if env("ROOTTRACE_EKS_CLUSTER_NAME") or env_bool("ROOTTRACE_EKS_CHECK", False):
        services.add("eks")
    if env("ROOTTRACE_NGINX_STATUS_URL") or env("ROOTTRACE_NGINX_STATUS_URLS") or process_matches(("nginx",)):
        services.add("nginx")
    if env("ROOTTRACE_APACHE_STATUS_URL") or env("ROOTTRACE_APACHE_STATUS_URLS") or process_matches(("apache2", "httpd")):
        services.add("apache")
    if env("ROOTTRACE_HAPROXY_STATS_URL") or env("ROOTTRACE_HAPROXY_STATS_URLS") or process_matches(("haproxy",)):
        services.add("haproxy")
    if env("ROOTTRACE_MONGODB_URI") or env("ROOTTRACE_MONGODB_TARGETS"):
        services.add("mongodb")
    if postgres_targets():
        services.add("postgres")
    if mysql_targets():
        services.add("mysql")
    if env("ROOTTRACE_REDIS_TARGETS"):
        services.add("redis")
    if env("ROOTTRACE_RABBITMQ_API_URL"):
        services.add("rabbitmq")
    if env("ROOTTRACE_ELASTICSEARCH_URLS") or env("ROOTTRACE_ELASTICSEARCH_URL"):
        services.add("elasticsearch")
    if env("ROOTTRACE_CLICKHOUSE_URLS") or env("ROOTTRACE_CLICKHOUSE_URL") or env("ROOTTRACE_CLICKHOUSE_TARGETS"):
        services.add("clickhouse")
    if env("ROOTTRACE_CASSANDRA_CONTACT_POINTS") or env("ROOTTRACE_CASSANDRA_TARGETS"):
        services.add("cassandra")
    if shutil.which("nvidia-smi"):
        services.add("nvidia")
    return sorted(services)


def diagnostic_payload(
    *,
    host: dict[str, Any],
    results: list[dict[str, Any]],
    batch_name: str,
    streaming: bool | None = None,
) -> dict[str, Any]:
    service = env("ROOTTRACE_SERVICE_NAME") or None
    service_type = env("ROOTTRACE_SERVICE_TYPE") or None
    return {
        "service": service,
        "service_type": service_type,
        "host": host,
        "results": results,
        "raw": {
            "collector_version": VERSION,
            "result_count": len(results),
            "batch": batch_name,
            "streaming": env_bool("ROOTTRACE_STREAMING", False) if streaming is None else streaming,
            "connection_model": "short_lived",
            "read_only": True,
        },
    }


def send_heartbeat(client: RootTraceClient, host: dict[str, Any], *, streaming: bool) -> None:
    enabled_config = {item.lower() for item in split_csv(env("ROOTTRACE_ENABLED_CHECKS"))}
    disabled = {item.lower() for item in split_csv(env("ROOTTRACE_DISABLED_CHECKS"))}
    enabled = [name for name, _ in CHECKERS if not enabled_config or name in enabled_config]
    checks = sorted(name for name in enabled if name not in disabled)
    response = client.post(
        "collectors/heartbeat",
        {
            "version": VERSION,
            "hostname": host["hostname"],
            "observed_services": observed_services([]),
            "metadata": {
                "mode": "read_only",
                "outbound_only": True,
                "streaming": streaming,
                "connection_model": "short_lived",
                "checks": checks,
                "platform": platform.platform(),
                "host": host,
                "collector_key_scope": "environment",
                "collector_key_reusable": True,
                # What this collector read, what the code's default was, and
                # which layer won. Sent so the product can show real values
                # instead of a hand-maintained guess at them.
                "tunables": tunable_report(),
            },
        },
    )
    applied = apply_server_tunables(response.get("tunables"))
    if applied:
        print(
            f"{utc_now()} applied {applied} tunable(s) from the server "
            f"(host environment variables still win)",
            flush=True,
        )
    server_time = response.get("server_time")
    if server_time:
        drift_result = check_time_drift(server_time)
        if drift_result:
            client.post(
                "collectors/ingest",
                diagnostic_payload(
                    host=host,
                    results=[drift_result],
                    batch_name="time",
                    streaming=False,
                ),
            )


def check_time_drift(server_time: str) -> dict[str, Any] | None:
    try:
        server = datetime.fromisoformat(server_time.replace("Z", "+00:00"))
        local = datetime.now(timezone.utc)
        drift_seconds = round(abs((local - server).total_seconds()), 2)
    except Exception:
        return None
    max_drift = env_float("ROOTTRACE_TIME_DRIFT_WARN_SECONDS", 5.0)
    status = "warn" if drift_seconds > max_drift else "pass"
    severity = "medium" if status == "warn" else "low"
    return result(
        "time",
        "Clock drift",
        status,
        severity,
        f"Collector clock differs from RootTrace API by {drift_seconds} seconds.",
        {"drift_seconds": drift_seconds, "max_allowed_seconds": max_drift},
    )


def send_streaming(client: RootTraceClient, host: dict[str, Any]) -> None:
    def payloads() -> Iterator[dict[str, Any]]:
        for batch_name, batch_results in iter_check_batches():
            yield diagnostic_payload(
                host=host,
                results=batch_results,
                batch_name=batch_name,
                streaming=True,
            )

    client.post_ndjson("collectors/ingest/stream", payloads())


def send_batch(client: RootTraceClient, host: dict[str, Any]) -> None:
    results = collect_results()
    client.post(
        "collectors/ingest",
        diagnostic_payload(
            host=host,
            results=results,
            batch_name="batch",
            streaming=False,
        ),
    )


def send_log_shipping_safe(client: RootTraceClient, host: dict[str, Any]) -> None:
    try:
        send_log_shipping(client, host)
    except Exception as exc:
        LAST_LOG_SHIP_STATS["last_error"] = str(exc)
        print(f"{utc_now()} log shipping failed: {exc}", file=sys.stderr, flush=True)


def send_once(client: RootTraceClient, streaming: bool) -> None:
    host = host_payload()
    send_heartbeat(client, host, streaming=streaming)
    if streaming:
        try:
            send_streaming(client, host)
            try:
                send_linux_audit(client, host)
                send_db_query_stats(client)
            except Exception as exc:
                LAST_LINUX_AUDIT_STATS["last_error"] = str(exc)
                print(f"{utc_now()} Linux audit ingest failed: {exc}", file=sys.stderr, flush=True)
            send_log_shipping_safe(client, host)
            return
        except RuntimeError as exc:
            if "HTTP 404" not in str(exc) and "HTTP 405" not in str(exc):
                raise
            print(f"{utc_now()} streaming ingest unavailable; falling back to batch ingest", file=sys.stderr, flush=True)
    send_batch(client, host)
    try:
        send_linux_audit(client, host)
        send_db_query_stats(client)
    except Exception as exc:
        LAST_LINUX_AUDIT_STATS["last_error"] = str(exc)
        print(f"{utc_now()} Linux audit ingest failed: {exc}", file=sys.stderr, flush=True)
    send_log_shipping_safe(client, host)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="RootTrace read-only diagnostics collector")
    parser.add_argument("--env-file", action="append", default=[], help="load ROOTTRACE_* settings from a systemd-style environment file")
    parser.add_argument("--once", action="store_true", help="run one heartbeat/ingest cycle and exit")
    parser.add_argument("--loop", action="store_true", help="run continuously")
    parser.add_argument("--batch", action="store_true", help="send one short-lived REST ingest payload per cycle")
    parser.add_argument("--streaming", action="store_true", help="opt in to newline-delimited streaming ingest for this process")
    parser.add_argument("--auditd-plugin", action="store_true", help="read Linux audit records from stdin and stream grouped JSON events")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    for env_file in args.env_file:
        try:
            load_env_file(env_file)
        except Exception as exc:
            print(f"{utc_now()} collector env file load failed: {exc}", file=sys.stderr, flush=True)
            return 2
    # No default destination. A collector that silently fell back to a vendor
    # URL would ship host diagnostics off-site the moment an operator forgot
    # this variable, so an unset or non-absolute value stops the process.
    api_url = env("ROOTTRACE_API_URL")
    parsed_api_url = urlparse(api_url)
    if parsed_api_url.scheme not in {"http", "https"} or not parsed_api_url.netloc:
        print(
            "ROOTTRACE_API_URL is required and must be an absolute http or https "
            "URL, for example https://roottrace.example.com/api.",
            file=sys.stderr,
        )
        return 2
    token = env("ROOTTRACE_COLLECTOR_TOKEN")
    if not token:
        print("ROOTTRACE_COLLECTOR_TOKEN is required.", file=sys.stderr)
        return 2
    interval = max(int(env("ROOTTRACE_INTERVAL_SECONDS", "60")), 15)
    timeout = max(int(env("ROOTTRACE_HTTP_TIMEOUT_SECONDS", "10")), 1)
    client = RootTraceClient(api_url=api_url, token=token, timeout=timeout)
    if args.auditd_plugin:
        return run_linux_audit_stdin_plugin(client)
    loop = args.loop or not args.once
    streaming = (args.streaming or env_bool("ROOTTRACE_STREAMING", False)) and not args.batch
    max_runtime_seconds = max(env_int("ROOTTRACE_MAX_RUNTIME_SECONDS", 0), 0)
    started_at = time.monotonic()
    while True:
        try:
            send_once(client, streaming)
            mode = "streaming" if streaming else "batch"
            print(f"{utc_now()} sent RootTrace collector heartbeat and diagnostics ({mode})", flush=True)
        except Exception as exc:
            print(f"{utc_now()} collector cycle failed: {exc}", file=sys.stderr, flush=True)
            if args.once:
                return 1
        if not loop:
            return 0
        if max_runtime_seconds:
            remaining = max_runtime_seconds - (time.monotonic() - started_at)
            if remaining <= 0:
                print(f"{utc_now()} collector reached ROOTTRACE_MAX_RUNTIME_SECONDS; exiting for supervisor restart.", flush=True)
                return 0
            time.sleep(max(1, min(interval, int(remaining))))
        else:
            time.sleep(interval)


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
from __future__ import annotations

import base64
import binascii
import datetime as dt
import json
import os
import re
import ssl
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


TOKEN_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
CA_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
DEFAULT_KUBECONFIG_PATHS = (
    "/etc/roottrace/kubeconfig",
    "/etc/kubernetes/admin.conf",
    "/etc/kubernetes/kubelet.conf",
    "/etc/rancher/k3s/k3s.yaml",
    "/etc/rancher/rke2/rke2.yaml",
    "/var/snap/microk8s/current/credentials/client.config",
    "/root/.kube/config",
    "~/.kube/config",
)
KUBECONFIG_ENV_NAMES = (
    "ROOTTRACE_KEDA_KUBECONFIG",
    "ROOTTRACE_KUBERNETES_KUBECONFIG",
    "ROOTTRACE_KUBECONFIG",
    "KUBECONFIG",
)
KEDA_KINDS = {"ScaledObject", "ScaledJob"}
KEDA_EVENT_RE = re.compile(r"(keda|scale|scaler|trigger|fallback|authentication|metric)", re.IGNORECASE)


class KubernetesApiError(RuntimeError):
    def __init__(self, status_code: int, path: str, body: str) -> None:
        super().__init__(f"Kubernetes API returned HTTP {status_code} for {path}: {body[:300]}")
        self.status_code = status_code
        self.path = path
        self.body = body[:1000]


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def env_bool(name: str, default: bool = False) -> bool:
    raw = env(name)
    if not raw:
        return default
    return raw.lower() in {"1", "true", "yes", "y", "on"}


def env_bool_opt(name: str) -> bool | None:
    raw = env(name)
    if not raw:
        return None
    return raw.lower() in {"1", "true", "yes", "y", "on"}


def env_int(name: str, default: int) -> int:
    try:
        return int(env(name, str(default)))
    except ValueError:
        return default


def env_csv(name: str) -> set[str]:
    return {item.strip() for item in env(name).split(",") if item.strip()}


def enabled_checks() -> set[str]:
    return {item.lower() for item in env_csv("ROOTTRACE_ENABLED_CHECKS")}


def disabled_checks() -> set[str]:
    return {item.lower() for item in env_csv("ROOTTRACE_DISABLED_CHECKS")}


def check_enabled(name: str) -> bool:
    check = name.lower()
    if check in disabled_checks():
        return False
    selected = enabled_checks()
    return not selected or check in selected


def kubernetes_checks_enabled() -> bool:
    return any(check_enabled(name) for name in ("kubernetes", "kubernetes_node", "eks", "keda"))


def kubeconfig_candidates() -> list[Path]:
    raw_paths: list[str] = []
    for name in KUBECONFIG_ENV_NAMES:
        configured = env(name)
        if configured:
            raw_paths.extend(item for item in configured.split(os.pathsep) if item.strip())
    raw_paths.extend(DEFAULT_KUBECONFIG_PATHS)

    candidates: list[Path] = []
    seen: set[str] = set()
    for raw_path in raw_paths:
        path = Path(raw_path.strip()).expanduser()
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


def keda_explicitly_enabled() -> bool:
    return env_bool("ROOTTRACE_KEDA_ENABLED", False)


def keda_monitor_enabled() -> bool:
    configured = env_bool_opt("ROOTTRACE_KEDA_ENABLED")
    if configured is not None:
        return configured
    if not kubernetes_checks_enabled():
        return False
    if env("KUBERNETES_SERVICE_HOST"):
        return True
    return any(path_exists(path) for path in kubeconfig_candidates())


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def parse_kubernetes_time(value: Any) -> dt.datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def object_namespace(item: dict[str, Any]) -> str:
    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    return str(metadata.get("namespace") or "default")


def object_name(item: dict[str, Any]) -> str:
    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    return str(metadata.get("name") or "unknown")


def trace_id(kind: str, namespace: str, name: str, signal: str) -> str:
    return f"keda:{kind.lower()}:{namespace}:{name}:{signal}"


def parse_scalar(value: str) -> Any:
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


def split_yaml_key_value(line: str) -> tuple[str, str] | None:
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
            pair = split_yaml_key_value(stripped)
            if pair is None:
                continue
            key, value = pair
            if key in {"clusters", "contexts", "users"}:
                section = key
                current = None
                nested_key = ""
                continue
            if key == "current-context":
                data[key] = parse_scalar(value)
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
            pair = split_yaml_key_value(remainder)
            if pair is None:
                continue
            key, value = pair
            if value == "":
                current[key] = {}
                nested_key = key
            else:
                current[key] = parse_scalar(value)
            continue

        if current is None:
            continue
        pair = split_yaml_key_value(stripped)
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
                nested[key] = parse_scalar(value)
            continue
        current[key] = parse_scalar(value)
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


def named_item(items: Any, name: str | None, nested_key: str) -> dict[str, Any] | None:
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


def decode_pem_data(value: Any, label: str) -> str:
    try:
        decoded = base64.b64decode("".join(str(value).split()), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RuntimeError(f"kubeconfig {label} was not valid base64 data") from exc
    return decoded.decode("utf-8", errors="replace")


def load_verify_locations_from_kubeconfig(context: ssl.SSLContext, path: Path, cluster: dict[str, Any]) -> None:
    ca_data = cluster.get("certificate-authority-data")
    if ca_data:
        context.load_verify_locations(cadata=decode_pem_data(ca_data, "certificate-authority-data"))
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


def load_cert_chain_from_kubeconfig(context: ssl.SSLContext, path: Path, user: dict[str, Any]) -> None:
    cert_data = user.get("client-certificate-data")
    key_data = user.get("client-key-data")
    if cert_data and key_data:
        cert_file = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False)
        key_file = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False)
        cert_path = key_path = ""
        try:
            cert_path = cert_file.name
            key_path = key_file.name
            cert_file.write(decode_pem_data(cert_data, "client-certificate-data"))
            key_file.write(decode_pem_data(key_data, "client-key-data"))
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
    context_name = env("ROOTTRACE_KEDA_KUBECONFIG_CONTEXT") or env("ROOTTRACE_KUBECONFIG_CONTEXT") or str(config.get("current-context") or "")
    context = named_item(config.get("contexts"), context_name or None, "context") or {}
    cluster_name = str(context.get("cluster") or "")
    user_name = str(context.get("user") or "")
    cluster = named_item(config.get("clusters"), cluster_name or None, "cluster")
    user = named_item(config.get("users"), user_name or None, "user") or {}
    if not isinstance(cluster, dict) or not cluster.get("server"):
        raise RuntimeError("kubeconfig did not contain a Kubernetes API server for the selected context")
    return cluster, user


def condition_for(item: dict[str, Any], condition_type: str) -> dict[str, Any] | None:
    status = item.get("status") if isinstance(item.get("status"), dict) else {}
    conditions = status.get("conditions") if isinstance(status.get("conditions"), list) else []
    for condition in conditions:
        if not isinstance(condition, dict):
            continue
        if str(condition.get("type") or "").lower() == condition_type.lower():
            return condition
    return None


def condition_is_true(item: dict[str, Any], condition_type: str) -> bool:
    condition = condition_for(item, condition_type)
    return str((condition or {}).get("status") or "").lower() == "true"


def condition_summary(item: dict[str, Any]) -> list[dict[str, Any]]:
    status = item.get("status") if isinstance(item.get("status"), dict) else {}
    conditions = status.get("conditions") if isinstance(status.get("conditions"), list) else []
    summary: list[dict[str, Any]] = []
    for condition in conditions:
        if not isinstance(condition, dict):
            continue
        summary.append(
            {
                "type": condition.get("type"),
                "status": condition.get("status"),
                "reason": condition.get("reason"),
                "message": condition.get("message"),
                "last_transition_time": condition.get("lastTransitionTime"),
            }
        )
    return summary


def item_details(item: dict[str, Any], kind: str, signal: str) -> dict[str, Any]:
    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    status = item.get("status") if isinstance(item.get("status"), dict) else {}
    spec = item.get("spec") if isinstance(item.get("spec"), dict) else {}
    namespace = str(metadata.get("namespace") or "default")
    name = str(metadata.get("name") or "unknown")
    return {
        "trace": {
            "id": trace_id(kind, namespace, name, signal),
            "source": "kubernetes.keda",
            "kind": kind,
            "namespace": namespace,
            "name": name,
            "signal": signal,
        },
        "namespace": namespace,
        "name": name,
        "generation": metadata.get("generation"),
        "observed_generation": status.get("observedGeneration"),
        "conditions": condition_summary(item),
        "scale_target": spec.get("scaleTargetRef"),
        "polling_interval_seconds": spec.get("pollingInterval"),
        "cooldown_period_seconds": spec.get("cooldownPeriod"),
        "min_replicas": spec.get("minReplicaCount"),
        "max_replicas": spec.get("maxReplicaCount"),
        "fallback": spec.get("fallback"),
        "triggers": [
            {
                "type": trigger.get("type"),
                "name": trigger.get("name"),
                "metric_type": trigger.get("metricType"),
            }
            for trigger in (spec.get("triggers") if isinstance(spec.get("triggers"), list) else [])
            if isinstance(trigger, dict)
        ],
        "last_active_time": status.get("lastActiveTime"),
        "external_metric_names": status.get("externalMetricNames"),
        "health": status.get("health"),
    }


class KubernetesClient:
    def __init__(self, base_url: str, headers: dict[str, str], context: ssl.SSLContext, timeout: float) -> None:
        self.base_url = base_url.rstrip("/")
        self.headers = headers
        self.context = context
        self.timeout = timeout

    @classmethod
    def from_environment(cls) -> "KubernetesClient":
        if any(env(name) for name in KUBECONFIG_ENV_NAMES):
            return cls.from_kubeconfig()
        host = env("KUBERNETES_SERVICE_HOST")
        port = env("KUBERNETES_SERVICE_PORT", "443")
        if host and TOKEN_PATH.exists():
            try:
                token = TOKEN_PATH.read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise RuntimeError(f"could not read Kubernetes service account token: {exc}") from exc
            context = ssl.create_default_context()
            if CA_PATH.exists():
                context.load_verify_locations(str(CA_PATH))
            return cls(
                f"https://{host}:{port}",
                {"Authorization": f"Bearer {token}"},
                context,
                env_int("ROOTTRACE_KEDA_API_TIMEOUT_SECONDS", 5),
            )
        return cls.from_kubeconfig()

    @classmethod
    def from_kubeconfig(cls) -> "KubernetesClient":
        errors: list[str] = []
        for path in kubeconfig_candidates():
            if not path_exists(path):
                continue
            try:
                config = load_kubeconfig(path)
                cluster, user = kubeconfig_context(config)
                context = kubeconfig_ssl_context(cluster)
                if cluster.get("insecure-skip-tls-verify") is not True:
                    load_verify_locations_from_kubeconfig(context, path, cluster)
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
                load_cert_chain_from_kubeconfig(context, path, user)
                if not headers and not (
                    user.get("client-certificate")
                    or user.get("client-key")
                    or user.get("client-certificate-data")
                    or user.get("client-key-data")
                ):
                    raise RuntimeError("kubeconfig user did not include token, basic auth, or client certificate credentials")
                return cls(
                    str(cluster["server"]),
                    headers,
                    context,
                    env_int("ROOTTRACE_KEDA_API_TIMEOUT_SECONDS", 5),
                )
            except Exception as exc:
                errors.append(f"{path}: {exc}")
        searched = ", ".join(str(path) for path in kubeconfig_candidates())
        if errors:
            raise RuntimeError(f"could not load a Kubernetes kubeconfig for KEDA monitoring. Errors: {'; '.join(errors)}")
        raise RuntimeError(
            "KEDA monitor could not find in-cluster credentials or a readable kubeconfig. "
            f"Searched: {searched}"
        )

    def get_json(self, path: str, query: dict[str, str] | None = None) -> dict[str, Any]:
        target = f"{self.base_url}{path}"
        if query:
            target = f"{target}?{urllib.parse.urlencode(query)}"
        headers = {
            "Accept": "application/json",
            "User-Agent": "roottrace-keda-monitor/1.0",
        }
        headers.update(self.headers)
        request = urllib.request.Request(
            target,
            headers=headers,
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                raw = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise KubernetesApiError(exc.code, path, body) from exc
        return json.loads(raw) if raw else {}


def api_items(client: KubernetesClient, path: str) -> tuple[list[dict[str, Any]], KubernetesApiError | None]:
    try:
        payload = client.get_json(path)
    except KubernetesApiError as exc:
        return [], exc
    except (OSError, TimeoutError, urllib.error.URLError, json.JSONDecodeError) as exc:
        return [], KubernetesApiError(0, path, str(exc))
    items = payload.get("items") if isinstance(payload.get("items"), list) else []
    return [item for item in items if isinstance(item, dict)], None


def namespace_allowed(namespace: str, include: set[str], exclude: set[str]) -> bool:
    if include and namespace not in include:
        return False
    return namespace not in exclude


def event_time(item: dict[str, Any]) -> dt.datetime | None:
    for key in ("lastTimestamp", "eventTime", "firstTimestamp"):
        parsed = parse_kubernetes_time(item.get(key))
        if parsed is not None:
            return parsed
    series = item.get("series") if isinstance(item.get("series"), dict) else {}
    return parse_kubernetes_time(series.get("lastObservedTime"))


def collect_warning_events(
    client: KubernetesClient,
    namespaces: set[str],
    *,
    lookback_minutes: int,
    max_events: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not env_bool("ROOTTRACE_KEDA_EVENTS_ENABLED", True):
        return [], []
    since = utc_now() - dt.timedelta(minutes=max(lookback_minutes, 1))
    events: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for namespace in sorted(namespaces):
        items, error = api_items(client, f"/api/v1/namespaces/{urllib.parse.quote(namespace, safe='')}/events")
        if error is not None:
            errors.append({"namespace": namespace, "status_code": error.status_code, "error": error.body})
            continue
        for item in items:
            if len(events) >= max_events:
                return events, errors
            when = event_time(item)
            if when is not None and when < since:
                continue
            involved = item.get("involvedObject") if isinstance(item.get("involvedObject"), dict) else {}
            kind = str(involved.get("kind") or "")
            reason = str(item.get("reason") or "")
            message = str(item.get("message") or "")
            event_type = str(item.get("type") or "")
            if event_type.lower() != "warning" and kind not in KEDA_KINDS and not KEDA_EVENT_RE.search(f"{reason} {message}"):
                continue
            if kind not in KEDA_KINDS and not KEDA_EVENT_RE.search(f"{reason} {message}"):
                continue
            events.append(
                {
                    "namespace": namespace,
                    "kind": kind or involved.get("apiVersion") or "Event",
                    "name": involved.get("name"),
                    "reason": reason,
                    "type": event_type,
                    "message": message[:500],
                    "last_timestamp": item.get("lastTimestamp") or item.get("eventTime") or item.get("firstTimestamp"),
                    "count": item.get("count"),
                }
            )
    return events, errors


def hpa_owner_key(hpa: dict[str, Any]) -> tuple[str, str] | None:
    metadata = hpa.get("metadata") if isinstance(hpa.get("metadata"), dict) else {}
    namespace = str(metadata.get("namespace") or "default")
    labels = metadata.get("labels") if isinstance(metadata.get("labels"), dict) else {}
    scaled_object = labels.get("scaledobject.keda.sh/name")
    if scaled_object:
        return namespace, str(scaled_object)
    owners = metadata.get("ownerReferences") if isinstance(metadata.get("ownerReferences"), list) else []
    for owner in owners:
        if not isinstance(owner, dict):
            continue
        if owner.get("kind") == "ScaledObject" and owner.get("name"):
            return namespace, str(owner["name"])
    name = str(metadata.get("name") or "")
    if name.startswith("keda-hpa-"):
        return namespace, name.removeprefix("keda-hpa-")
    return None


def hpa_replica_gap(hpa: dict[str, Any]) -> int:
    status = hpa.get("status") if isinstance(hpa.get("status"), dict) else {}
    desired = int(status.get("desiredReplicas") or 0)
    current = int(status.get("currentReplicas") or 0)
    return max(desired - current, 0)


def keda_operator_pod_summary(client: KubernetesClient, namespace: str) -> tuple[dict[str, Any], KubernetesApiError | None]:
    pods, error = api_items(client, f"/api/v1/namespaces/{urllib.parse.quote(namespace, safe='')}/pods")
    if error is not None:
        return {"pods": [], "unready_count": 0, "restart_count": 0}, error
    rows: list[dict[str, Any]] = []
    unready = 0
    restarts = 0
    for pod in pods:
        metadata = pod.get("metadata") if isinstance(pod.get("metadata"), dict) else {}
        labels = metadata.get("labels") if isinstance(metadata.get("labels"), dict) else {}
        name = str(metadata.get("name") or "")
        if not (
            labels.get("app.kubernetes.io/part-of") == "keda"
            or str(labels.get("app.kubernetes.io/name") or "").startswith("keda")
            or name.startswith("keda-")
        ):
            continue
        status = pod.get("status") if isinstance(pod.get("status"), dict) else {}
        container_statuses = status.get("containerStatuses") if isinstance(status.get("containerStatuses"), list) else []
        pod_restarts = sum(int(container.get("restartCount") or 0) for container in container_statuses if isinstance(container, dict))
        ready = all(bool(container.get("ready")) for container in container_statuses if isinstance(container, dict)) and bool(container_statuses)
        if not ready:
            unready += 1
        restarts += pod_restarts
        rows.append(
            {
                "namespace": metadata.get("namespace"),
                "name": name,
                "phase": status.get("phase"),
                "ready": ready,
                "restart_count": pod_restarts,
            }
        )
    return {"pods": rows, "unready_count": unready, "restart_count": restarts}, None


def emit_keda_metric(
    emit,
    *,
    name: str,
    value: int | float,
    label: str,
    resource: str,
    resource_label: str,
    details: dict[str, Any],
    unit: str = "",
    warning: int | float | None = None,
    error: int | float | None = None,
    status: str | None = None,
    severity: str | None = None,
    message: str | None = None,
) -> None:
    emit(
        check="keda",
        check_label="KEDA autoscaling",
        name=name,
        value=value,
        label=label,
        unit=unit,
        warning=warning,
        error=error,
        higher_is_worse=True,
        service="keda",
        service_type="kubernetes_autoscaler",
        resource=resource,
        resource_label=resource_label,
        details=details,
        status=status,
        severity=severity,
        message=message,
    )


def collect_metrics(emit) -> None:
    if not keda_monitor_enabled():
        return

    try:
        client = KubernetesClient.from_environment()
    except RuntimeError as exc:
        emit_keda_metric(
            emit,
            name="keda_api_available",
            value=1,
            label="KEDA API unavailable",
            warning=1,
            error=1,
            resource="KEDA API",
            resource_label="KEDA API",
            severity="high",
            message="KEDA monitoring could not reach the Kubernetes API.",
            details={"error": str(exc), "trace": {"id": "keda:cluster:api:api_available", "source": "kubernetes.keda"}},
        )
        return

    include_namespaces = env_csv("ROOTTRACE_KEDA_NAMESPACES")
    exclude_namespaces = env_csv("ROOTTRACE_KEDA_EXCLUDE_NAMESPACES")
    max_resources = max(env_int("ROOTTRACE_KEDA_MAX_RESOURCES", 200), 1)
    event_lookback = max(env_int("ROOTTRACE_KEDA_EVENT_LOOKBACK_MINUTES", 15), 1)
    max_events = max(env_int("ROOTTRACE_KEDA_MAX_EVENTS", 100), 1)
    keda_namespace = env("ROOTTRACE_KEDA_NAMESPACE", "kube-system")

    scaled_objects, scaled_objects_error = api_items(client, "/apis/keda.sh/v1alpha1/scaledobjects")
    scaled_jobs, scaled_jobs_error = api_items(client, "/apis/keda.sh/v1alpha1/scaledjobs")
    if (
        not keda_explicitly_enabled()
        and scaled_objects_error
        and scaled_jobs_error
        and scaled_objects_error.status_code == 404
        and scaled_jobs_error.status_code == 404
    ):
        return
    if scaled_objects_error and scaled_jobs_error:
        emit_keda_metric(
            emit,
            name="keda_crd_api_errors",
            value=1,
            label="KEDA CRD API errors",
            warning=1,
            error=1,
            resource="KEDA CRDs",
            resource_label="KEDA API",
            severity="high",
            message="KEDA custom resources could not be read from the Kubernetes API.",
            details={
                "scaledobjects_error": scaled_objects_error.body,
                "scaledjobs_error": scaled_jobs_error.body,
                "trace": {"id": "keda:cluster:api:crd_api", "source": "kubernetes.keda"},
            },
        )
        return
    if scaled_objects_error and scaled_objects_error.status_code != 404:
        emit_keda_metric(
            emit,
            name="keda_scaledobject_api_error",
            value=1,
            label="ScaledObject API errors",
            warning=1,
            error=1,
            resource="ScaledObject API",
            resource_label="KEDA API",
            severity="medium",
            message="KEDA ScaledObject resources could not be read.",
            details={
                "status_code": scaled_objects_error.status_code,
                "error": scaled_objects_error.body,
                "trace": {"id": "keda:cluster:api:scaledobjects", "source": "kubernetes.keda"},
            },
        )
    if scaled_jobs_error and scaled_jobs_error.status_code != 404:
        emit_keda_metric(
            emit,
            name="keda_scaledjob_api_error",
            value=1,
            label="ScaledJob API errors",
            warning=1,
            error=1,
            resource="ScaledJob API",
            resource_label="KEDA API",
            severity="medium",
            message="KEDA ScaledJob resources could not be read.",
            details={
                "status_code": scaled_jobs_error.status_code,
                "error": scaled_jobs_error.body,
                "trace": {"id": "keda:cluster:api:scaledjobs", "source": "kubernetes.keda"},
            },
        )

    scaled_objects = [
        item
        for item in scaled_objects
        if namespace_allowed(object_namespace(item), include_namespaces, exclude_namespaces)
    ][:max_resources]
    scaled_jobs = [
        item
        for item in scaled_jobs
        if namespace_allowed(object_namespace(item), include_namespaces, exclude_namespaces)
    ][:max_resources]

    namespaces = {object_namespace(item) for item in [*scaled_objects, *scaled_jobs]}
    if not include_namespaces:
        namespaces.add(keda_namespace)

    events, event_errors = collect_warning_events(
        client,
        namespaces,
        lookback_minutes=event_lookback,
        max_events=max_events,
    )
    events_by_resource: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for event in events:
        key = (
            str(event.get("kind") or ""),
            str(event.get("namespace") or ""),
            str(event.get("name") or ""),
        )
        events_by_resource.setdefault(key, []).append(event)

    hpas, hpa_error = api_items(client, "/apis/autoscaling/v2/horizontalpodautoscalers")
    hpa_by_scaled_object: dict[tuple[str, str], dict[str, Any]] = {}
    if hpa_error is None:
        for hpa in hpas:
            key = hpa_owner_key(hpa)
            if key is not None:
                hpa_by_scaled_object[key] = hpa

    operator_summary, operator_error = keda_operator_pod_summary(client, keda_namespace)

    emit_keda_metric(
        emit,
        name="keda_scaledobject_count",
        value=len(scaled_objects),
        label="ScaledObjects",
        resource="ScaledObjects",
        resource_label="KEDA resources",
        details={
            "namespaces": sorted({object_namespace(item) for item in scaled_objects}),
            "trace": {"id": "keda:cluster:scaledobjects:count", "source": "kubernetes.keda"},
        },
    )
    emit_keda_metric(
        emit,
        name="keda_scaledjob_count",
        value=len(scaled_jobs),
        label="ScaledJobs",
        resource="ScaledJobs",
        resource_label="KEDA resources",
        details={
            "namespaces": sorted({object_namespace(item) for item in scaled_jobs}),
            "trace": {"id": "keda:cluster:scaledjobs:count", "source": "kubernetes.keda"},
        },
    )

    not_ready_count = 0
    fallback_count = 0
    paused_count = 0
    hpa_gap_total = 0

    for item in scaled_objects:
        namespace = object_namespace(item)
        name = object_name(item)
        resource = f"ScaledObject {namespace}/{name}"
        ready = condition_is_true(item, "Ready")
        fallback = condition_is_true(item, "Fallback")
        paused = condition_is_true(item, "Paused")
        details = item_details(item, "ScaledObject", "ready")
        details["warning_events"] = events_by_resource.get(("ScaledObject", namespace, name), [])[:10]
        if not ready:
            not_ready_count += 1
        if fallback:
            fallback_count += 1
        if paused:
            paused_count += 1
        emit_keda_metric(
            emit,
            name="keda_scaledobject_not_ready",
            value=0 if ready else 1,
            label="ScaledObject not ready",
            warning=1,
            error=1,
            resource=resource,
            resource_label="ScaledObject",
            message=(
                f"KEDA ScaledObject {namespace}/{name} is ready."
                if ready
                else f"KEDA ScaledObject {namespace}/{name} is not ready."
            ),
            details=details,
        )
        fallback_details = item_details(item, "ScaledObject", "fallback")
        emit_keda_metric(
            emit,
            name="keda_scaledobject_fallback",
            value=1 if fallback else 0,
            label="ScaledObject fallback",
            warning=1,
            error=1,
            resource=f"{resource} fallback",
            resource_label="ScaledObject",
            message=(
                f"KEDA ScaledObject {namespace}/{name} is not in fallback."
                if not fallback
                else f"KEDA ScaledObject {namespace}/{name} is in fallback mode."
            ),
            details=fallback_details,
        )
        paused_details = item_details(item, "ScaledObject", "paused")
        emit_keda_metric(
            emit,
            name="keda_scaledobject_paused",
            value=1 if paused else 0,
            label="ScaledObject paused",
            warning=1,
            error=3,
            resource=f"{resource} paused",
            resource_label="ScaledObject",
            details=paused_details,
        )
        hpa = hpa_by_scaled_object.get((namespace, name))
        gap = hpa_replica_gap(hpa) if isinstance(hpa, dict) else 0
        hpa_gap_total += gap
        hpa_details = item_details(item, "ScaledObject", "hpa_replica_gap")
        hpa_details.update({"hpa": hpa, "hpa_api_error": getattr(hpa_error, "body", None)})
        emit_keda_metric(
            emit,
            name="keda_hpa_replica_gap",
            value=gap,
            label="HPA replica gap",
            unit="replicas",
            warning=env_int("ROOTTRACE_KEDA_HPA_GAP_WARNING", 1),
            error=env_int("ROOTTRACE_KEDA_HPA_GAP_ERROR", 3),
            resource=f"{resource} HPA",
            resource_label="ScaledObject",
            details=hpa_details,
        )

    scaledjob_not_ready = 0
    for item in scaled_jobs:
        namespace = object_namespace(item)
        name = object_name(item)
        ready = condition_is_true(item, "Ready")
        if not ready:
            scaledjob_not_ready += 1
        details = item_details(item, "ScaledJob", "ready")
        details["warning_events"] = events_by_resource.get(("ScaledJob", namespace, name), [])[:10]
        emit_keda_metric(
            emit,
            name="keda_scaledjob_not_ready",
            value=0 if ready else 1,
            label="ScaledJob not ready",
            warning=1,
            error=1,
            resource=f"ScaledJob {namespace}/{name}",
            resource_label="ScaledJob",
            message=(
                f"KEDA ScaledJob {namespace}/{name} is ready."
                if ready
                else f"KEDA ScaledJob {namespace}/{name} is not ready."
            ),
            details=details,
        )

    emit_keda_metric(
        emit,
        name="keda_warning_event_count",
        value=len(events),
        label="KEDA warning events",
        unit="events",
        warning=env_int("ROOTTRACE_KEDA_EVENT_WARNING", 1),
        error=env_int("ROOTTRACE_KEDA_EVENT_ERROR", 5),
        resource="KEDA warning events",
        resource_label="KEDA events",
        details={
            "lookback_minutes": event_lookback,
            "events": events[:max_events],
            "event_read_errors": event_errors,
            "trace": {"id": "keda:cluster:events:warning_events", "source": "kubernetes.keda"},
        },
    )

    emit_keda_metric(
        emit,
        name="keda_operator_unready_pod_count",
        value=int(operator_summary.get("unready_count") or 0),
        label="KEDA operator unready pods",
        unit="pods",
        warning=1,
        error=1,
        resource="KEDA operator",
        resource_label="KEDA operator",
        details={
            "namespace": keda_namespace,
            "pods": operator_summary.get("pods"),
            "api_error": getattr(operator_error, "body", None),
            "trace": {"id": f"keda:{keda_namespace}:operator:unready_pods", "source": "kubernetes.keda"},
        },
    )
    emit_keda_metric(
        emit,
        name="keda_operator_restart_count",
        value=int(operator_summary.get("restart_count") or 0),
        label="KEDA operator restarts",
        unit="restarts",
        warning=env_int("ROOTTRACE_KEDA_OPERATOR_RESTART_WARNING", 1),
        error=env_int("ROOTTRACE_KEDA_OPERATOR_RESTART_ERROR", 3),
        resource="KEDA operator restarts",
        resource_label="KEDA operator",
        details={
            "namespace": keda_namespace,
            "pods": operator_summary.get("pods"),
            "api_error": getattr(operator_error, "body", None),
            "trace": {"id": f"keda:{keda_namespace}:operator:restarts", "source": "kubernetes.keda"},
        },
    )

    finding_count = (
        not_ready_count
        + fallback_count
        + paused_count
        + scaledjob_not_ready
        + len(events)
        + int(operator_summary.get("unready_count") or 0)
    )
    emit_keda_metric(
        emit,
        name="keda_health_summary",
        value=finding_count,
        label="KEDA health findings",
        unit="findings",
        warning=1,
        error=3,
        resource="KEDA health summary",
        resource_label="KEDA",
        details={
            "scaledobject_count": len(scaled_objects),
            "scaledjob_count": len(scaled_jobs),
            "scaledobject_not_ready_count": not_ready_count,
            "scaledobject_fallback_count": fallback_count,
            "scaledobject_paused_count": paused_count,
            "scaledjob_not_ready_count": scaledjob_not_ready,
            "hpa_replica_gap_total": hpa_gap_total,
            "warning_event_count": len(events),
            "operator_unready_pod_count": operator_summary.get("unready_count"),
            "operator_restart_count": operator_summary.get("restart_count"),
            "hpa_api_error": getattr(hpa_error, "body", None),
            "event_read_errors": event_errors,
            "trace": {"id": "keda:cluster:summary:health", "source": "kubernetes.keda"},
        },
    )

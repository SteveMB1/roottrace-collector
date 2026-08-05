# AWS's mirror of the official image, not Docker Hub directly: CodeBuild hosts
# share NAT addresses and hit Docker Hub's anonymous pull rate limit. The digest
# is the same one Docker Hub serves for 3.12-slim, so the pin is unchanged.
FROM public.ecr.aws/docker/library/python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

# ROOTTRACE_API_URL is deliberately absent: the collector requires it and
# stops without it, so a container can never ship diagnostics to a destination
# the operator did not name.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ROOTTRACE_INTERVAL_SECONDS=60 \
    ROOTTRACE_STREAMING=false \
    ROOTTRACE_CUSTOM_METRICS_PATHS=/app/additional_monitors \
    ROOTTRACE_CUSTOM_METRICS_MAX_FILES=16

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      gcc \
      libdbus-1-3 \
      libdbus-1-dev \
      libglib2.0-0 \
      libglib2.0-dev \
      libsystemd-dev \
      libsystemd0 \
      pkg-config && \
    rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    dbus-python==1.4.0 \
    dnspython==2.8.0 \
    mysql-connector-python==9.7.0 \
    psycopg[binary]==3.3.4 \
    pymongo==4.17.0 \
    systemd-python==235 \
    typing-extensions==4.16.0 && \
    apt-get purge -y --auto-remove gcc libdbus-1-dev libglib2.0-dev libsystemd-dev pkg-config && \
    rm -rf /root/.cache

RUN addgroup --system roottrace && \
    adduser --system --ingroup roottrace --home /nonexistent --shell /usr/sbin/nologin roottrace && \
    install -d -o roottrace -g roottrace -m 0750 /var/lib/roottrace-collector

WORKDIR /app
COPY roottrace_collector.py /app/roottrace_collector.py
COPY additional_monitors /app/additional_monitors
RUN chmod 0555 /app/roottrace_collector.py
RUN chmod -R 0555 /app/additional_monitors

ARG ROOTTRACE_COLLECTOR_IMAGE_VERSION=dev
ARG ROOTTRACE_COLLECTOR_IMAGE_REVISION=unknown

LABEL org.opencontainers.image.title="RootTrace Agent" \
      org.opencontainers.image.description="RootTrace host and Kubernetes collector" \
      org.opencontainers.image.version="${ROOTTRACE_COLLECTOR_IMAGE_VERSION}" \
      org.opencontainers.image.revision="${ROOTTRACE_COLLECTOR_IMAGE_REVISION}"

VOLUME ["/var/lib/roottrace-collector"]

USER roottrace:roottrace

HEALTHCHECK --interval=60s --timeout=10s --start-period=20s --retries=3 \
  CMD python /app/roottrace_collector.py --help >/dev/null 2>&1 || exit 1

ENTRYPOINT ["python", "/app/roottrace_collector.py"]
CMD ["--loop"]

# AFTERLIFE application container.
# No network at all (network_mode: none in compose): it only listens on a unix
# socket that is shared with the tor container. It runs as an unprivileged user
# on a read-only root filesystem.
# setup.sh pins the base image to a digest (PYTHON_IMAGE=python@sha256:...).
ARG PYTHON_IMAGE=python:3.12-slim-trixie
FROM ${PYTHON_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY requirements.txt .
# Hash-locked, binary-only install: a tampered or substituted package fails the build.
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: -r requirements.txt \
    && rm requirements.txt

RUN groupadd -g 10001 afterlife \
    && useradd -r -u 10001 -g 10001 -M -d /app -s /usr/sbin/nologin afterlife \
    && mkdir -p /app/data /app/secrets /run/afterlife \
    && chown 10001:10001 /app/data /app/secrets /run/afterlife \
    && chmod 0700 /app/data /app/secrets \
    && chmod 0755 /run/afterlife

COPY --chown=root:root server.py /app/server.py
COPY --chown=root:root afterlife_server /app/afterlife_server

USER 10001:10001
ENTRYPOINT ["python", "/app/server.py"]

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install tor. apt installs it and creates the debian-tor user automatically.
RUN apt-get update \
    && apt-get install -y --no-install-recommends tor \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files.
COPY server.py .
COPY client.py .
COPY README.md .
COPY LICENSE .

# Copy tor configuration and entrypoint.
COPY torrc /etc/tor/torrc
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Create the afterlife app user and necessary directories.
# The hidden service directory and tor data directory are created here so that
# volume mounts in docker-compose inherit the correct ownership at runtime.
# Actual chown/chmod is handled by entrypoint.sh at startup.
RUN useradd -r -u 10001 -m afterlife \
    && mkdir -p /app/data \
    && mkdir -p /var/lib/tor/afterlife_hs \
    && mkdir -p /var/lib/tor/data \
    && chown -R afterlife:afterlife /app/data

# Entrypoint runs as root to start tor, then drops to afterlife for the server.
# No port is exposed to the Docker host - the service is only reachable via Tor.
ENTRYPOINT ["/entrypoint.sh"]
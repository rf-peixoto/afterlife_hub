# Tor onion-service container.
# tor comes from the Tor Project's own repository (current 0.4.8+ builds with the
# proof-of-work module), verified against the published signing-key fingerprint.
# setup.sh pins the base image to a digest (DEBIAN_IMAGE=debian@sha256:...).
ARG DEBIAN_IMAGE=debian:trixie-slim
FROM ${DEBIAN_IMAGE}

ARG TOR_KEY_FPR=A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89
ARG INSTALL_VANGUARDS=1
# vanguards is not packaged in Debian 13, so it is fetched from PyPI as two
# exact, hash-verified pure-Python files (no pip, no build step).
ARG VANGUARDS_WHL_URL=https://files.pythonhosted.org/packages/py2.py3/v/vanguards/vanguards-0.3.1-py2.py3-none-any.whl
ARG VANGUARDS_WHL_SHA256=ef3751d47263483a040486cff920841e937fdea4f892c1791191dfd8c9f20ebf
ARG STEM_TGZ_URL=https://files.pythonhosted.org/packages/source/s/stem/stem-1.8.2.tar.gz
ARG STEM_TGZ_SHA256=83fb19ffd4c9f82207c006051480389f80af221a7e4783000aedec4e384eb582

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates gpg gpg-agent curl tini; \
    curl -fsSL "https://deb.torproject.org/torproject.org/${TOR_KEY_FPR}.asc" -o /tmp/tor.asc; \
    gpg --batch --show-keys --with-colons /tmp/tor.asc | awk -F: '$1=="fpr"{print $10; exit}' > /tmp/fpr; \
    test "$(cat /tmp/fpr)" = "${TOR_KEY_FPR}"; \
    gpg --batch --dearmor < /tmp/tor.asc > /usr/share/keyrings/deb.torproject.org-keyring.gpg; \
    . /etc/os-release; \
    echo "deb [signed-by=/usr/share/keyrings/deb.torproject.org-keyring.gpg] https://deb.torproject.org/torproject.org ${VERSION_CODENAME} main" \
        > /etc/apt/sources.list.d/tor.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends tor deb.torproject.org-keyring; \
    if [ "${INSTALL_VANGUARDS}" = "1" ]; then \
        apt-get install -y --no-install-recommends python3; \
        mkdir -p /opt/vanguards /tmp/vg; \
        curl -fsSL "${VANGUARDS_WHL_URL}" -o /tmp/vg/vanguards.whl; \
        curl -fsSL "${STEM_TGZ_URL}" -o /tmp/vg/stem.tar.gz; \
        echo "${VANGUARDS_WHL_SHA256}  /tmp/vg/vanguards.whl" | sha256sum -c -; \
        echo "${STEM_TGZ_SHA256}  /tmp/vg/stem.tar.gz" | sha256sum -c -; \
        python3 -m zipfile -e /tmp/vg/vanguards.whl /opt/vanguards; \
        tar -xzf /tmp/vg/stem.tar.gz -C /tmp/vg; \
        mv /tmp/vg/stem-1.8.2/stem /opt/vanguards/stem; \
        python3 -W ignore -m compileall -q /opt/vanguards; \
        rm -rf /tmp/vg; \
    fi; \
    apt-get purge -y gpg gpg-agent curl; apt-get autoremove -y; \
    rm -rf /var/lib/apt/lists/* /tmp/tor.asc /tmp/fpr; \
    tor --version; \
    tor --list-modules

# Fixed uid/gid 10002 so the host can own the onion key directory without
# guessing. Renumbered AFTER installation so the package's own user creation
# (adduser --system) is never confused by a pre-existing account.
RUN set -eux; \
    old_uid="$(id -u debian-tor)"; old_gid="$(id -g debian-tor)"; \
    groupmod -g 10002 debian-tor; usermod -u 10002 -g 10002 debian-tor; \
    find / -xdev \( -uid "$old_uid" -o -gid "$old_gid" \) -exec chown -h 10002:10002 {} + 2>/dev/null || true

RUN mkdir -p /var/lib/tor/hs /var/lib/tor/data /run/afterlife \
    && chown -R 10002:10002 /var/lib/tor \
    && chmod 0700 /var/lib/tor/hs /var/lib/tor/data \
    && chown 10001:10001 /run/afterlife

COPY docker/tor/torrc /etc/tor/torrc
COPY docker/tor/entrypoint.sh /usr/local/bin/tor-entrypoint
COPY docker/tor/run-vanguards.py /usr/local/bin/run-vanguards
RUN chmod 0755 /usr/local/bin/tor-entrypoint /usr/local/bin/run-vanguards && chmod 0644 /etc/tor/torrc \
    && if [ "${INSTALL_VANGUARDS}" = "1" ]; then /usr/local/bin/run-vanguards --help >/dev/null; fi

USER 10002:10002
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/tor-entrypoint"]

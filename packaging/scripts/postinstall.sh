#!/bin/sh
# nfpm/dpkg post-install: refresh systemd and create runtime directories.
set -e

if command -v systemd-tmpfiles >/dev/null 2>&1; then
    systemd-tmpfiles --create /usr/lib/tmpfiles.d/zeroshield.conf >/dev/null 2>&1 || true
fi

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

exit 0

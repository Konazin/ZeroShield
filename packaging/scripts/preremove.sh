#!/bin/sh
# nfpm/dpkg pre-remove: stop units so no daemon keeps the old binary open.
set -e

if [ -d /run/systemd/system ]; then
    if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
        systemctl disable --now zeroshield-scan.timer >/dev/null 2>&1 || true
        systemctl stop zeroshieldd.service >/dev/null 2>&1 || true
    fi
fi

exit 0

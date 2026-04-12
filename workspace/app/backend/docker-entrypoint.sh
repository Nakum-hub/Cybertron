#!/bin/sh
set -eu

if [ "${REPORT_STORAGE_DRIVER:-local}" = "local" ]; then
  storage_path="${REPORT_STORAGE_LOCAL_PATH:-/srv/cybertron/uploads/reports}"
  if [ "$(id -u)" -eq 0 ]; then
    su-exec node mkdir -p "${storage_path}"
  else
    mkdir -p "${storage_path}"
  fi
fi

if [ "$(id -u)" -eq 0 ]; then
  exec su-exec node "$@"
fi

exec "$@"

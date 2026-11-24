#!/usr/bin/env bash
# Start (or recreate) exodon. Tokens come from the environment: the variables
# your .env names in EXODON_<NAME>_JMAP_TOKEN_ENV (read-only, reads + push) and
# EXODON_<NAME>_JMAP_WRITE_TOKEN_ENV (live mode), passed into the container by
# docker-compose.override.yml. If docker/up.local.sh exists (gitignored), it
# runs instead, so a secrets-manager wrapper can live there. It must call
# `docker compose up -d --build "$@"` itself, not this script.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p ../var
if [ -f ./up.local.sh ] && [ -z "${EXODON_UP_LOCAL:-}" ]; then
  EXODON_UP_LOCAL=1 exec bash ./up.local.sh "$@"
fi
exec docker compose up -d --build "$@"

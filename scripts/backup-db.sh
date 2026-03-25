#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="/opt/lab-platform"
ENV_FILE="$BASE_DIR/.env"
BACKUP_DIR="$BASE_DIR/data/backups"
TIMESTAMP="$(date +%F_%H%M%S)"
OUT_FILE="$BACKUP_DIR/lptdb_${TIMESTAMP}.dump"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: Missing $ENV_FILE"
  exit 1
fi

mkdir -p "$BACKUP_DIR"

set -a
source "$ENV_FILE"
set +a

: "${POSTGRES_USER:?Missing POSTGRES_USER in .env}"
: "${POSTGRES_DB:?Missing POSTGRES_DB in .env}"
: "${POSTGRES_PASSWORD:?Missing POSTGRES_PASSWORD in .env}"

echo "Creating backup: $OUT_FILE"

PGPASSWORD="$POSTGRES_PASSWORD" pg_dump \
  -h 127.0.0.1 \
  -p 55432 \
  -U "$POSTGRES_USER" \
  -Fc "$POSTGRES_DB" \
  -f "$OUT_FILE"

echo "Backup completed:"
ls -lh "$OUT_FILE"


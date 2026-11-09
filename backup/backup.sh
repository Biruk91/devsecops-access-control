#!/usr/bin/env bash
# ============================================================
# Nightly database backup (Module 9, section 10).
# ============================================================
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-./backups}"
mkdir -p "$BACKUP_DIR"

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
file="$BACKUP_DIR/dinedesk-$stamp.dump"

docker compose exec -T db sh -c 'pg_dump --format=custom -U postgres dinedesk' > "$file"
(cd "$BACKUP_DIR" && sha256sum "$(basename "$file")" > "$(basename "$file").sha256")
echo "Backup written: $file"

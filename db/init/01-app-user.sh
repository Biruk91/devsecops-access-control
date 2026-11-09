#!/bin/sh
# ============================================================
# Runs ONCE, when the database volume is first created.
# Creates the API's own login with only what it needs - not the superuser.
# ============================================================
set -eu

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    CREATE ROLE dinedesk_app WITH LOGIN PASSWORD '$APP_DB_PASSWORD' NOSUPERUSER NOCREATEDB NOCREATEROLE;
    GRANT CONNECT ON DATABASE "$POSTGRES_DB" TO dinedesk_app;
    GRANT USAGE, CREATE ON SCHEMA public TO dinedesk_app;
EOSQL

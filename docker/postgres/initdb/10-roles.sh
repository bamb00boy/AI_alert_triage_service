#!/bin/bash
# Runs once, on first database initialisation, as the owner (POSTGRES_USER).
# Creates the least-privilege role the services connect as; migrations/grants.sql
# gives it table privileges after each migration.
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -v app_password="$APP_DB_PASSWORD" <<-'EOSQL'
	CREATE ROLE triage_app LOGIN PASSWORD :'app_password';
	GRANT CONNECT ON DATABASE triage TO triage_app;
	ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO triage_app;
	ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO triage_app;
EOSQL

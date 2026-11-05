#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
set -eu
: "${ANONCE_ANON_DB_PASSWORD:?ANONCE_ANON_DB_PASSWORD is required}"
: "${ANONCE_MEMBER_DB_PASSWORD:?ANONCE_MEMBER_DB_PASSWORD is required}"
# psql's quoted variable expansion is SQL-literal safe, including apostrophes.
psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --set=ON_ERROR_STOP=1 --set=anon_password="$ANONCE_ANON_DB_PASSWORD" --set=member_password="$ANONCE_MEMBER_DB_PASSWORD" <<'SQL'
CREATE ROLE anonce_anon LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD :'anon_password';
CREATE ROLE anonce_member LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD :'member_password';
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT CREATE, USAGE ON SCHEMA public TO anonce_member;
SQL
# Database identifier is quoted by PostgreSQL's format(), not by the shell.
psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --set=ON_ERROR_STOP=1 --set=db="$POSTGRES_DB" <<'SQL'
SELECT format('GRANT CREATE ON DATABASE %I TO anonce_member', :'db') \gexec
SQL

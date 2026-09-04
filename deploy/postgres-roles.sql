-- Least privilege for the PostgreSQL tier (ADR-0095).
--
-- Run once, as a superuser, before the first migration. It creates the two roles the
-- deployment actually needs and gives each of them the smallest set of rights that lets it
-- do its job — so that a leaked application password is not also a way to drop the schema,
-- read `pg_authid`, write files with `COPY … TO PROGRAM`, or install an extension.
--
--   psql "$ADMIN_URL" -v app_password="'…'" -v backup_password="'…'" -f deploy/postgres-roles.sql
--
-- Then point the application at the app role and nothing else:
--
--   DATABASE_URL=postgres://symvolon_app:…@db:5432/symvolon
--
-- The application owns its schema because it runs its own migrations at boot
-- (`src/server/db/migrate.ts`), which is a deliberate trade: a role that can create a table
-- is a role that can drop one, and the alternative — a separate migration role and a
-- deployment step that runs it — is a step an operator can forget in the wrong direction.
-- What the app role does *not* get is any right outside its own schema.

CREATE ROLE symvolon_app LOGIN PASSWORD :app_password;

-- Read-only, for `pg_dump` and for anyone answering a question. It can never write.
CREATE ROLE symvolon_backup LOGIN PASSWORD :backup_password;

-- The database belongs to the app role; `template0` avoids inheriting anything local.
CREATE DATABASE symvolon OWNER symvolon_app TEMPLATE template0;

-- Nobody connects to this database except the two roles above.
REVOKE ALL ON DATABASE symvolon FROM PUBLIC;
GRANT CONNECT ON DATABASE symvolon TO symvolon_app, symvolon_backup;

\connect symvolon

-- `public` is writable by every role by default on PostgreSQL below 15. Take that away and
-- give the application a schema of its own instead.
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA IF NOT EXISTS symvolon AUTHORIZATION symvolon_app;
ALTER ROLE symvolon_app IN DATABASE symvolon SET search_path = symvolon;
ALTER ROLE symvolon_backup IN DATABASE symvolon SET search_path = symvolon;

GRANT USAGE ON SCHEMA symvolon TO symvolon_backup;
GRANT SELECT ON ALL TABLES IN SCHEMA symvolon TO symvolon_backup;
ALTER DEFAULT PRIVILEGES FOR ROLE symvolon_app IN SCHEMA symvolon
  GRANT SELECT ON TABLES TO symvolon_backup;

-- Neither role is a superuser, may create a database or a role, or may bypass row security.
ALTER ROLE symvolon_app NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;
ALTER ROLE symvolon_backup NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;

-- Role bootstrap. Run ONCE as a superuser, before any migration.
--
-- TENANT-001, build item 091. Two roles, and the split is the point:
--
--   certwatch_migrator  owns the schema, runs migrations, has DDL rights.
--   certwatch_app       what the application connects as. NOBYPASSRLS,
--                       no DDL, no superuser.
--
-- If the application connected as the owner, FORCE ROW LEVEL SECURITY would
-- still apply (that is what FORCE means) but the app could also DROP the
-- policies. An application one SQL injection away from ALTER TABLE ... DISABLE
-- ROW LEVEL SECURITY is not isolated; it is politely asking to be.

-- NOBYPASSRLS is the default, and stated anyway so a reader does not have to
-- know that. NOSUPERUSER matters just as much: a superuser bypasses RLS
-- regardless of rolbypassrls, which is the usual way this check is defeated.
CREATE ROLE certwatch_app
    LOGIN PASSWORD 'certwatch_dev_password_not_for_production'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;

CREATE ROLE certwatch_migrator
    LOGIN PASSWORD 'certwatch_dev_password_not_for_production'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;

GRANT CONNECT ON DATABASE certwatch TO certwatch_app, certwatch_migrator;

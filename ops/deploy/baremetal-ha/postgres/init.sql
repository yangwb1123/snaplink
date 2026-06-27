-- One-time application bootstrap, run against the Patroni LEADER after the
-- cluster forms. Idempotent: safe to re-run. The sso-server's own migrate
-- runner creates the schema on first boot; this only provisions the role + db.
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sso') THEN
    CREATE ROLE sso LOGIN PASSWORD 'change-me-sso';
  END IF;
END $$;

SELECT 'CREATE DATABASE sso OWNER sso'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'sso')\gexec

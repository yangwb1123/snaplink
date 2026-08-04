-- One-time application bootstrap, run against the Patroni leader with
-- SSO_DB_PASSWORD, BILLING_DB_PASSWORD and STRIPE_DB_PASSWORD present in the
-- psql environment.
-- psql's \getenv keeps credentials out of this file and the command line.
\set ON_ERROR_STOP on
\getenv sso_password SSO_DB_PASSWORD
\getenv billing_password BILLING_DB_PASSWORD
\getenv stripe_password STRIPE_DB_PASSWORD

SELECT format('CREATE ROLE sso LOGIN PASSWORD %L', :'sso_password')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sso')\gexec
SELECT format('ALTER ROLE sso PASSWORD %L', :'sso_password')\gexec

SELECT format('CREATE ROLE billing LOGIN PASSWORD %L', :'billing_password')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'billing')\gexec
SELECT format('ALTER ROLE billing PASSWORD %L', :'billing_password')\gexec

SELECT format('CREATE ROLE stripe_adapter LOGIN PASSWORD %L', :'stripe_password')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'stripe_adapter')\gexec
SELECT format('ALTER ROLE stripe_adapter PASSWORD %L', :'stripe_password')\gexec

SELECT 'CREATE DATABASE sso OWNER sso'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'sso')\gexec
SELECT 'CREATE DATABASE billing OWNER billing'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'billing')\gexec
SELECT 'CREATE DATABASE stripe_adapter OWNER stripe_adapter'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'stripe_adapter')\gexec

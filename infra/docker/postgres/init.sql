-- OfSec V3 — PostgreSQL 17 + TimescaleDB initialization
-- This runs on first container startup

-- Enable TimescaleDB extension
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;

-- Enable useful extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";        -- Trigram text search
CREATE EXTENSION IF NOT EXISTS "btree_gin";       -- GIN index support
CREATE EXTENSION IF NOT EXISTS "citext";          -- Case-insensitive text

-- Create enum types
CREATE TYPE scan_status AS ENUM ('pending', 'running', 'completed', 'failed', 'cancelled');
CREATE TYPE severity_level AS ENUM ('critical', 'high', 'medium', 'low', 'info');
CREATE TYPE alert_status AS ENUM ('new', 'acknowledged', 'investigating', 'resolved', 'false_positive');
CREATE TYPE attack_status AS ENUM ('planned', 'running', 'success', 'failed', 'aborted');

-- Log initialization
DO $$ BEGIN RAISE NOTICE 'OfSec V3 database initialized with TimescaleDB'; END $$;

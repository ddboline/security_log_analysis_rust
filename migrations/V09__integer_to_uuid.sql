CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE intrusion_log DROP COLUMN id;
ALTER TABLE intrusion_log ADD COLUMN id UUID PRIMARY KEY DEFAULT gen_random_uuid();

ALTER TABLE systemd_log_messages DROP COLUMN id;
ALTER TABLE systemd_log_messages ADD COLUMN id UUID PRIMARY KEY DEFAULT gen_random_uuid();

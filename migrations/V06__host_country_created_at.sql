ALTER TABLE host_country ADD COLUMN created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now();

CREATE TABLE systemd_log_messages (
    id SERIAL PRIMARY KEY UNIQUE NOT NULL,
    log_level TEXT NOT NULL,
    log_unit TEXT,
    log_message TEXT NOT NULL,
    log_timestamp TIMESTAMP WITH TIME ZONE NOT NULL
);
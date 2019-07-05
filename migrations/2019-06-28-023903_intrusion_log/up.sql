-- Your SQL goes here
CREATE TABLE intrusion_log (
    id SERIAL PRIMARY KEY UNIQUE NOT NULL,
    service TEXT NOT NULL,
    server TEXT NOT NULL,
    datetime TIMESTAMP WITH TIME ZONE NOT NULL,
    host VARCHAR(60) NOT NULL,
    username VARCHAR(15),

    UNIQUE (service, server, datetime, host, username),
);

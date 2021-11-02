-- Your SQL goes here
CREATE TABLE host_country (
    host TEXT PRIMARY KEY UNIQUE NOT NULL,
    code VARCHAR(2) NOT NULL,
    ipaddr VARCHAR(15)
);

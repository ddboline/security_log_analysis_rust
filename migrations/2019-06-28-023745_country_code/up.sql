-- Your SQL goes here
CREATE TABLE country_code (
    code VARCHAR(2) PRIMARY KEY UNIQUE NOT NULL,
    country VARCHAR(50) NOT NULL
);

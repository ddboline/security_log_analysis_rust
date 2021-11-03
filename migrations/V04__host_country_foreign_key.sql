-- Your SQL goes here
ALTER TABLE host_country ADD FOREIGN KEY (code) REFERENCES country_code(code);
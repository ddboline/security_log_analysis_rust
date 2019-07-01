#!/bin/bash

DB="security_logs"

TABLES="
country_code
host_country
intrusion_log
"

mkdir -p backup/

for T in $TABLES;
do
    psql $DB -c "DELETE FROM $T";
done

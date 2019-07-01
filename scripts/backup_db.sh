#!/bin/bash

DB="security_logs"
BUCKET=security-log-analysis-db-backup

TABLES="
country_code
host_country
intrusion_log
"

mkdir -p backup/

for T in $TABLES;
do
    psql $DB -c "COPY $T TO STDOUT" | gzip > backup/${T}.sql.gz
    aws s3 cp backup/${T}.sql.gz s3://${BUCKET}/${T}.sql.gz
done

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
    aws s3 cp s3://${BUCKET}/${T}.sql.gz backup/${T}.sql.gz
    gzip -dc backup/${T}.sql.gz | psql $DB -c "COPY $T FROM STDIN"
done

CREATE TABLE key_item_cache (
    s3_key TEXT NOT NULL UNIQUE PRIMARY KEY,
    s3_etag TEXT,
    s3_timestamp BIGINT,
    s3_size BIGINT,
    local_etag TEXT,
    local_timestamp BIGINT,
    local_size BIGINT,
    do_download BOOLEAN NOT NULL DEFAULT false,
    do_upload BOOLEAN NOT NULL DEFAULT false
)
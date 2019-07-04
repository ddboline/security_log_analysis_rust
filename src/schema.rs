table! {
    country_code (code) {
        code -> Varchar,
        country -> Varchar,
    }
}

table! {
    host_country (host) {
        host -> Varchar,
        code -> Varchar,
        ipaddr -> Nullable<Varchar>,
    }
}

table! {
    intrusion_log (id) {
        id -> Int4,
        service -> Text,
        server -> Text,
        datetime -> Timestamptz,
        host -> Varchar,
        username -> Nullable<Varchar>,
    }
}

allow_tables_to_appear_in_same_query!(country_code, host_country, intrusion_log,);

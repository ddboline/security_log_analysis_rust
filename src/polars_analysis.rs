use anyhow::{format_err, Error};
use chrono::{Duration, NaiveDateTime, Utc};
use futures::TryStreamExt;
use log::info;
use polars::{
    chunked_array::ops::SortOptions,
    df as dataframe,
    frame::DataFrame,
    io::{
        parquet::{ParquetReader, ParquetWriter},
        SerReader,
    },
    lazy::{dsl::functions::col, frame::IntoLazy},
    prelude::{lit, LazyFrame, NamedFrom, ScanArgsParquet, UniqueKeepStrategy},
};
use postgres_query::{query, FromSqlRow};
use stack_string::{format_sstr, StackString};
use std::{fs::File, path::Path};
use time::UtcOffset;

use crate::{pgpool::PgPool, CountryCount, DateTimeType, Host, Service};

fn stackstring_to_series(col: &[StackString]) -> Vec<&str> {
    col.iter().map(StackString::as_str).collect()
}

fn opt_stackstring_to_series(col: &[Option<StackString>]) -> Vec<Option<&str>> {
    col.iter()
        .map(|o| o.as_ref().map(StackString::as_str))
        .collect()
}

/// # Errors
/// Return error if db query fails
pub async fn insert_db_into_parquet(
    pool: &PgPool,
    outdir: &Path,
) -> Result<Vec<StackString>, Error> {
    #[derive(FromSqlRow)]
    struct Wrap {
        year: i32,
        month: i32,
        count: i64,
    }

    #[derive(FromSqlRow)]
    struct IntrusionLogRow {
        service: StackString,
        server: StackString,
        datetime: DateTimeType,
        host: StackString,
        username: Option<StackString>,
        code: Option<StackString>,
        country: Option<StackString>,
    }

    #[derive(Default)]
    struct IntrusionLogColumns {
        service: Vec<StackString>,
        server: Vec<StackString>,
        datetime: Vec<NaiveDateTime>,
        host: Vec<StackString>,
        username: Vec<Option<StackString>>,
        code: Vec<Option<StackString>>,
        country: Vec<Option<StackString>>,
    }

    impl IntrusionLogColumns {
        fn new(cap: usize) -> Self {
            Self {
                service: Vec::with_capacity(cap),
                server: Vec::with_capacity(cap),
                datetime: Vec::with_capacity(cap),
                host: Vec::with_capacity(cap),
                username: Vec::with_capacity(cap),
                code: Vec::with_capacity(cap),
                country: Vec::with_capacity(cap),
            }
        }
    }

    let mut output = Vec::new();

    let query = query!(
        r#"
            SELECT cast(extract(year from datetime at time zone 'utc') as int) as year,
                   cast(extract(month from datetime at time zone 'utc') as int) as month,
                   count(*) as count
            FROM intrusion_log
            GROUP BY 1,2
        "#
    );
    let conn = pool.get().await?;
    let rows: Vec<Wrap> = query.fetch(&conn).await?;
    for Wrap { year, month, count } in rows {
        output.push(format_sstr!("year {} month {}", year, month));
        let query = query!(
            r#"
                SELECT a.*, b.code, c.country
                FROM intrusion_log a
                LEFT JOIN host_country b ON a.host = b.host
                LEFT JOIN country_code c ON b.code = c.code
                WHERE cast(extract(year from a.datetime at time zone 'utc') as int) = $year
                  AND cast(extract(month from a.datetime at time zone 'utc') as int) = $month
            "#,
            year = year,
            month = month,
        );

        let intrusion_rows: IntrusionLogColumns = query
            .fetch_streaming::<IntrusionLogRow, _>(&conn)
            .await?
            .try_fold(
                IntrusionLogColumns::new(count as usize),
                |mut acc, row| async move {
                    acc.service.push(row.service);
                    acc.server.push(row.server);

                    let d = row.datetime.to_offset(UtcOffset::UTC);
                    let datetime =
                        NaiveDateTime::from_timestamp_opt(d.unix_timestamp(), d.nanosecond())
                            .expect("Invalid timestamp");
                    acc.datetime.push(datetime);
                    acc.host.push(row.host);
                    acc.username.push(row.username);
                    acc.code.push(row.code);
                    acc.country.push(row.country);

                    Ok(acc)
                },
            )
            .await?;

        let new_df = dataframe!(
            "service" => stackstring_to_series(&intrusion_rows.service),
            "server" => stackstring_to_series(&intrusion_rows.server),
            "host" => stackstring_to_series(&intrusion_rows.host),
            "username" => opt_stackstring_to_series(&intrusion_rows.username),
            "code" => opt_stackstring_to_series(&intrusion_rows.code),
            "country" => opt_stackstring_to_series(&intrusion_rows.country),
            "datetime" => &intrusion_rows.datetime,
        )?;

        output.push(format_sstr!("{:?}", new_df.shape()));

        let filename = format_sstr!("intrusion_log_{year:04}_{month:02}.parquet");
        let file = outdir.join(&filename);
        let mut df = if file.exists() {
            let df = ParquetReader::new(File::open(&file)?).finish()?;
            output.push(format_sstr!("{:?}", df.shape()));
            let existing_entries = df.shape().0;
            let updated_df = df
                .vstack(&new_df)?
                .unique(None, UniqueKeepStrategy::First, None)?;
            if existing_entries == updated_df.shape().0 {
                continue;
            }
            updated_df
        } else {
            new_df
        };
        ParquetWriter::new(File::create(&file)?).finish(&mut df)?;
        output.push(format_sstr!("wrote {} {:?}", filename, df.shape()));
    }
    Ok(output)
}

/// # Errors
/// Returns error if input/output doesn't exist or cannot be read
pub fn merge_parquet_files(input: &Path, output: &Path) -> Result<(), Error> {
    info!("input {:?} output {:?}", input, output);
    if !input.exists() {
        return Err(format_err!("input {input:?} does not exist"));
    }
    if !output.exists() {
        return Err(format_err!("output {output:?} does not exist"));
    }
    let df0 = ParquetReader::new(File::open(input)?).finish()?;
    info!("input {:?}", df0.shape());
    let df1 = ParquetReader::new(File::open(output)?).finish()?;
    info!("output {:?}", df1.shape());
    let mut df = df1
        .vstack(&df0)?
        .unique(None, UniqueKeepStrategy::First, None)?;
    info!("final {:?}", df.shape());
    ParquetWriter::new(File::create(output)?).finish(&mut df)?;
    info!("wrote {:?} {:?}", output, df.shape());
    Ok(())
}

/// # Errors
/// Return error if db query fails
pub fn read_parquet_files(
    input: &Path,
    service: Option<Service>,
    server: Option<Host>,
    ndays: Option<i32>,
) -> Result<Vec<CountryCount>, Error> {
    if !input.exists() {
        return Err(format_err!("Path does not exists"));
    }
    let input_path = Path::new(input);
    let input_files = if input_path.is_dir() {
        let v: Result<Vec<_>, Error> = input
            .read_dir()?
            .map(|p| p.map(|p| p.path()).map_err(Into::into))
            .collect();
        let mut v = v?;
        v.sort();
        v
    } else {
        vec![input.to_path_buf()]
    };
    let country: Vec<&str> = Vec::new();
    let country_count: Vec<u32> = Vec::new();
    let mut df = dataframe!(
        "country" => country,
        "country_count" => country_count,
    )?;
    for input_file in input_files {
        let new_df = get_country_count(&input_file, service, server, ndays)?;
        df = df.vstack(&new_df)?;
    }
    let df = df
        .lazy()
        .groupby(["country"])
        .agg([col("country_count").sum().alias("count")])
        .sort(
            "count",
            SortOptions {
                descending: true,
                ..SortOptions::default()
            },
        )
        .collect()?;
    let country_iter = df.column("country")?.utf8()?.into_iter();
    let count_iter = df.column("count")?.u32()?.into_iter();
    let code_count: Vec<_> = country_iter
        .zip(count_iter)
        .filter_map(|(country, count)| {
            country.map(|country| {
                let country = country.into();
                let count = i64::from(count.unwrap_or(0));
                CountryCount { country, count }
            })
        })
        .collect();
    Ok(code_count)
}

fn get_country_count(
    input: &Path,
    service: Option<Service>,
    server: Option<Host>,
    ndays: Option<i32>,
) -> Result<DataFrame, Error> {
    let args = ScanArgsParquet::default();
    let mut df = LazyFrame::scan_parquet(input, args)?;
    if let Some(service) = service {
        df = df.filter(col("service").eq(lit(service.to_str())));
    }
    if let Some(server) = server {
        df = df.filter(col("server").eq(lit(server.to_str())));
    }
    if let Some(ndays) = ndays {
        let begin_timestamp = (Utc::now() - Duration::days(i64::from(ndays)))
            .naive_utc()
            .timestamp_millis();
        df = df.filter(
            col("datetime")
                .dt()
                .timestamp(polars::prelude::TimeUnit::Milliseconds)
                .gt(begin_timestamp),
        );
    }
    let df = df
        .groupby(["country"])
        .agg([col("datetime").count().alias("country_count")])
        .collect()?;
    Ok(df)
}

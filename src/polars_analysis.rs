use anyhow::{format_err, Error};
use chrono::{Duration, NaiveDateTime, Utc};
use futures::TryStreamExt;
use log::info;
use polars::{
    chunked_array::ops::SortOptions,
    datatypes::TimeUnit,
    lazy::{dsl::functions::col, frame::IntoLazy},
    prelude::{UniqueKeepStrategy, Utf8Chunked},
};
use postgres_query::{query, FromSqlRow};
use stack_string::{format_sstr, StackString};
use std::{fs::File, path::Path};
use time::UtcOffset;

use polars::{
    chunked_array::builder::NewChunkedArray,
    datatypes::{BooleanChunked, DatetimeChunked, UInt32Chunked},
    frame::DataFrame,
    io::{
        parquet::{ParquetReader, ParquetWriter},
        SerReader,
    },
    series::IntoSeries,
};

use crate::{pgpool::PgPool, CountryCount, DateTimeType, Host, Service};

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
                IntrusionLogColumns {
                    service: Vec::with_capacity(count as usize),
                    server: Vec::with_capacity(count as usize),
                    datetime: Vec::with_capacity(count as usize),
                    host: Vec::with_capacity(count as usize),
                    username: Vec::with_capacity(count as usize),
                    code: Vec::with_capacity(count as usize),
                    country: Vec::with_capacity(count as usize),
                },
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

        let columns = vec![
            Utf8Chunked::from_slice("service", &intrusion_rows.service).into_series(),
            Utf8Chunked::from_slice("server", &intrusion_rows.server).into_series(),
            Utf8Chunked::from_slice("host", &intrusion_rows.host).into_series(),
            Utf8Chunked::from_slice_options("username", &intrusion_rows.username).into_series(),
            Utf8Chunked::from_slice_options("code", &intrusion_rows.code).into_series(),
            Utf8Chunked::from_slice_options("country", &intrusion_rows.country).into_series(),
            DatetimeChunked::from_naive_datetime(
                "datetime",
                intrusion_rows.datetime,
                TimeUnit::Milliseconds,
            )
            .into_series(),
        ];

        let new_df = DataFrame::new(columns)?;
        output.push(format_sstr!("{:?}", new_df.shape()));

        let filename = format_sstr!("intrusion_log_{year:04}_{month:02}.parquet");
        let file = outdir.join(&filename);
        let mut df = if file.exists() {
            let df = ParquetReader::new(File::open(&file)?).finish()?;
            output.push(format_sstr!("{:?}", df.shape()));
            df.vstack(&new_df)?
                .unique(None, UniqueKeepStrategy::First, None)?
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
    let mut df = df1.vstack(&df0)?.unique(None, UniqueKeepStrategy::First, None)?;
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
            .into_iter()
            .map(|p| p.map(|p| p.path()).map_err(Into::into))
            .collect();
        let mut v = v?;
        v.sort();
        v
    } else {
        vec![input.to_path_buf()]
    };
    let country: Vec<&str> = Vec::new();
    let country = Utf8Chunked::from_slice("country", &country).into_series();
    let country_count = UInt32Chunked::from_slice("country_count", &[]).into_series();
    let mut df = DataFrame::new(vec![country, country_count])?;
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
    let mut df = ParquetReader::new(File::open(input)?).finish()?;
    if let Some(service) = service {
        let mask: Vec<_> = df
            .column("service")?
            .utf8()?
            .into_iter()
            .map(|x| x == Some(service.to_str()))
            .collect();
        let mask = BooleanChunked::from_slice("service_mask", &mask);
        df = df.filter(&mask)?;
    }
    if let Some(server) = server {
        let mask: Vec<_> = df
            .column("server")?
            .utf8()?
            .into_iter()
            .map(|x| x == Some(server.to_str()))
            .collect();
        let mask = BooleanChunked::from_slice("server_mask", &mask);
        df = df.filter(&mask)?;
    }
    if let Some(ndays) = ndays {
        let begin_timestamp = (Utc::now() - Duration::days(i64::from(ndays)))
            .naive_utc()
            .timestamp_millis();
        let mask: Vec<_> = df
            .column("datetime")?
            .datetime()?
            .into_iter()
            .map(|x| x.map(|d| d > begin_timestamp))
            .collect();
        let mask = BooleanChunked::from_slice_options("datetime_mask", &mask);
        df = df.filter(&mask)?;
    }
    let df = df.groupby(["country"])?.select(["country"]).count()?;
    Ok(df)
}

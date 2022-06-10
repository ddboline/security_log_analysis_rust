use anyhow::{format_err, Error};
use chrono::{Duration, NaiveDateTime, Utc};
use polars::{
    datatypes::TimeUnit,
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
pub async fn insert_db_into_parquet(pool: &PgPool, outdir: &Path) -> Result<(), Error> {
    #[derive(FromSqlRow)]
    struct Wrap {
        year: i32,
        month: i32,
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

    let query = query!(
        r#"
            SELECT cast(extract(year from datetime at time zone 'utc') as int) as year,
                   cast(extract(month from datetime at time zone 'utc') as int) as month
            FROM intrusion_log
            GROUP BY 1,2
        "#
    );
    let conn = pool.get().await?;
    let rows: Vec<Wrap> = query.fetch(&conn).await?;
    for Wrap { year, month } in rows {
        println!("year {} month {}", year, month);
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
        let rows: Vec<IntrusionLogRow> = query.fetch(&conn).await?;

        let mut columns = Vec::new();
        let v: Vec<_> = rows.iter().map(|x| &x.service).collect();
        columns.push(Utf8Chunked::from_slice("service", &v).into_series());
        let v: Vec<_> = rows.iter().map(|x| &x.server).collect();
        columns.push(Utf8Chunked::from_slice("server", &v).into_series());
        let v: Vec<_> = rows.iter().map(|x| &x.host).collect();
        columns.push(Utf8Chunked::from_slice("host", &v).into_series());
        let v: Vec<_> = rows.iter().map(|x| x.username.as_ref()).collect();
        columns.push(Utf8Chunked::from_slice_options("username", &v).into_series());
        let v: Vec<_> = rows.iter().map(|x| x.code.as_ref()).collect();
        columns.push(Utf8Chunked::from_slice_options("code", &v).into_series());
        let v: Vec<_> = rows.iter().map(|x| x.country.as_ref()).collect();
        columns.push(Utf8Chunked::from_slice_options("country", &v).into_series());
        let v: Vec<_> = rows
            .iter()
            .map(|x| {
                let d = x.datetime.to_offset(UtcOffset::UTC);
                NaiveDateTime::from_timestamp(d.unix_timestamp(), d.nanosecond())
            })
            .collect();
        columns.push(
            DatetimeChunked::from_naive_datetime("datetime", v, TimeUnit::Milliseconds)
                .into_series(),
        );

        let new_df = DataFrame::new(columns)?;
        println!("{:?}", new_df.shape());

        let filename = format_sstr!("intrusion_log_{year:04}_{month:02}.parquet");
        let file = outdir.join(&filename);
        let mut df = if file.exists() {
            let df = ParquetReader::new(File::open(&file)?).finish()?;
            println!("{:?}", df.shape());
            df.vstack(&new_df)?
                .unique(None, UniqueKeepStrategy::First)?
        } else {
            new_df
        };
        ParquetWriter::new(File::create(&file)?).finish(&mut df)?;
        println!("wrote {} {:?}", filename, df.shape());
    }
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
    let mut df = df.groupby(["country"])?.sum()?;
    df.rename("country_count_sum", "count")?;
    df.sort_in_place(&["count"], true)?;
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
    let mut df = ParquetReader::new(File::open(&input)?).finish()?;
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

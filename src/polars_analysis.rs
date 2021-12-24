use anyhow::{format_err, Error};
use chrono::{DateTime, Datelike, Duration, Utc};
use flate2::read::GzDecoder;
use itertools::Itertools;
use log::debug;
use polars::prelude::{ChunkCompare, Utf8Chunked};
use postgres_query::{query, FromSqlRow};
use stack_string::StackString;
use std::{
    fs::File,
    io::{BufRead, BufReader, Cursor},
    path::{Path, PathBuf},
};
use structopt::StructOpt;

use polars::{
    chunked_array::{builder::NewChunkedArray, temporal::naive_datetime_to_datetime},
    datatypes::{AnyValue, BooleanChunked, DataType, DatetimeChunked, Int32Chunked, UInt32Chunked},
    frame::DataFrame,
    io::{
        csv::{CsvReader, NullValues},
        parquet::{ParquetReader, ParquetWriter},
        SerReader,
    },
    series::{IntoSeries, Series},
};

use crate::{config::Config, pgpool::PgPool, s3_sync::GarminSync};

#[derive(StructOpt)]
pub enum AnalysisOpts {
    Sync {
        #[structopt(short = "d", long = "directory")]
        directory: Option<PathBuf>,
    },
    Etl {
        #[structopt(short = "i", long = "input")]
        input: Option<PathBuf>,
        #[structopt(short = "d", long = "directory")]
        directory: Option<PathBuf>,
    },
    Db {
        #[structopt(short = "d", long = "directory")]
        directory: Option<PathBuf>,
    },
    Read {
        #[structopt(short = "d", long = "directory")]
        directory: Option<PathBuf>,
        #[structopt(short = "s", long = "service")]
        service: Option<StackString>,
        #[structopt(short = "t", long = "server")]
        server: Option<StackString>,
        #[structopt(short = "n", long = "ndays")]
        ndays: Option<i32>,
    },
}

fn read_tsv_file(input: &Path, outdir: &Path) -> Result<(), Error> {
    let gz = GzDecoder::new(File::open(input)?);
    let mut buf = Vec::new();
    let mut gzbuf = BufReader::new(gz);
    let mut line = Vec::new();
    let mut nlines = 0;
    while gzbuf.read_until(b'\n', &mut line)? > 0 {
        buf.extend_from_slice(&line);
        line.clear();
        nlines += 1;
        if nlines >= 1_000_000 {
            write_to_parquet(&buf, outdir)?;
            buf.clear();
            nlines = 0;
        }
    }
    if !buf.is_empty() {
        write_to_parquet(&buf, outdir)?;
    }
    Ok(())
}

fn write_to_parquet(buf: &[u8], outdir: &Path) -> Result<(), Error> {
    let cursor = Cursor::new(&buf);
    let mut csv = CsvReader::new(cursor)
        .with_null_values(Some(NullValues::AllColumns("\\N".into())))
        .with_delimiter(b'\t')
        .has_header(false)
        .with_parse_dates(true)
        .with_dtypes_slice(Some(&[
            DataType::Int64,
            DataType::Utf8,
            DataType::Utf8,
            DataType::Utf8,
            DataType::Utf8,
            DataType::Utf8,
            DataType::Utf8,
        ]))
        .finish()?;
    csv.set_column_names(&[
        "id",
        "service",
        "server",
        "datetime_str",
        "host",
        "username",
        "code",
        "country",
    ])?;
    let s = csv.get_columns().get(3).unwrap();
    let v: Vec<_> = s
        .utf8()?
        .into_iter()
        .map(|x| {
            let x = x.unwrap();
            let d = DateTime::parse_from_str(x, "%Y-%m-%d %H:%M:%S%.f%#z").unwrap();
            d.naive_utc()
        })
        .collect();
    csv.drop_in_place("id")?;
    csv.drop_in_place("datetime_str")?;

    let dt = DatetimeChunked::new_from_naive_datetime("datetime", &v).into_series();
    csv.with_column(dt)?;

    let y: Vec<_> = v.iter().map(Datelike::year).collect();
    let y = Int32Chunked::new_from_slice("year", &y).into_series();
    csv.with_column(y)?;

    let m: Vec<_> = v.iter().map(Datelike::month).collect();
    let m = UInt32Chunked::new_from_slice("month", &m).into_series();
    csv.with_column(m)?;

    let year_month_group = csv.groupby(("year", "month"))?;
    let ymg = year_month_group.groups()?;
    for idx in 0..ymg.shape().0 {
        if let Some(row) = ymg.get(idx) {
            let year = match row.get(0) {
                Some(AnyValue::Int32(y)) => y,
                _ => panic!("Unexpected"),
            };
            let month = match row.get(1) {
                Some(AnyValue::UInt32(m)) => m,
                _ => panic!("Unexpected"),
            };
            let indicies = year_month_group
                .get_groups()
                .get(idx)
                .unwrap()
                .1
                .iter()
                .map(|i| *i as usize);
            let mut new_csv = csv.take_iter(indicies)?;
            new_csv.drop_in_place("year")?;
            new_csv.drop_in_place("month")?;
            let filename = format!("intrusion_log_{:04}_{:02}.parquet", year, month);
            let file = outdir.join(&filename);
            let df = if file.exists() {
                ParquetReader::new(File::open(&file)?)
                    .finish()?
                    .vstack(&new_csv)?
                    .drop_duplicates(true, None)?
            } else {
                new_csv
            };
            ParquetWriter::new(File::create(&file)?).finish(&df)?;
            debug!("wrote {} {:?}", filename, df.shape());
        }
    }
    Ok(())
}

async fn insert_db_into_parquet(pool: &PgPool, outdir: &Path) -> Result<(), Error> {
    #[derive(FromSqlRow)]
    struct Wrap {
        year: i32,
        month: i32,
    }

    #[derive(FromSqlRow)]
    struct IntrusionLogRow {
        service: StackString,
        server: StackString,
        datetime: DateTime<Utc>,
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
        columns.push(Utf8Chunked::new_from_slice("service", &v).into_series());
        let v: Vec<_> = rows.iter().map(|x| &x.server).collect();
        columns.push(Utf8Chunked::new_from_slice("server", &v).into_series());
        let v: Vec<_> = rows.iter().map(|x| &x.host).collect();
        columns.push(Utf8Chunked::new_from_slice("host", &v).into_series());
        let v: Vec<_> = rows.iter().map(|x| x.username.as_ref()).collect();
        columns.push(Utf8Chunked::new_from_opt_slice("username", &v).into_series());
        let v: Vec<_> = rows.iter().map(|x| x.code.as_ref()).collect();
        columns.push(Utf8Chunked::new_from_opt_slice("code", &v).into_series());
        let v: Vec<_> = rows.iter().map(|x| x.country.as_ref()).collect();
        columns.push(Utf8Chunked::new_from_opt_slice("country", &v).into_series());
        let v: Vec<_> = rows.iter().map(|x| x.datetime.naive_utc()).collect();
        columns.push(DatetimeChunked::new_from_naive_datetime("datetime", &v).into_series());

        let new_df = DataFrame::new(columns)?;
        println!("{:?}", new_df.shape());

        let filename = format!("intrusion_log_{:04}_{:02}.parquet", year, month);
        let file = outdir.join(&filename);
        let df = if file.exists() {
            let df = ParquetReader::new(File::open(&file)?).finish()?;
            println!("{:?}", df.shape());
            df.vstack(&new_df)?.drop_duplicates(true, None)?
        } else {
            new_df
        };
        ParquetWriter::new(File::create(&file)?).finish(&df)?;
        println!("wrote {} {:?}", filename, df.shape());
    }
    Ok(())
}

#[derive(Debug)]
pub struct CodeCount {
    pub country: StackString,
    pub count: u32,
}

pub fn read_parquet_files(
    input: &Path,
    service: Option<&str>,
    server: Option<&str>,
    ndays: Option<i32>,
) -> Result<Vec<CodeCount>, Error> {
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
    let country = Utf8Chunked::new_from_slice("country", &country).into_series();
    let country_count = UInt32Chunked::new_from_slice("country_count", &[]).into_series();
    let mut df = DataFrame::new(vec![country, country_count])?;
    for input_file in input_files {
        let new_df = get_country_count(&input_file, service, server, ndays)?;
        df = df.vstack(&new_df)?;
    }
    let mut df = df.groupby("country")?.sum()?;
    df.rename("country_count_sum", "count")?;
    df.sort_in_place("count", true)?;
    let country_iter = df.column("country")?.utf8()?.into_iter();
    let count_iter = df.column("count")?.u32()?.into_iter();
    let code_count: Vec<_> = country_iter
        .zip(count_iter)
        .filter_map(|(country, count)| {
            country.map(|country| {
                let country = country.into();
                let count = count.unwrap_or(0);
                CodeCount { country, count }
            })
        })
        .collect();
    Ok(code_count)
}

fn get_country_count(
    input: &Path,
    service: Option<&str>,
    server: Option<&str>,
    ndays: Option<i32>,
) -> Result<DataFrame, Error> {
    let mut df = ParquetReader::new(File::open(&input)?).finish()?;
    if let Some(service) = service {
        let mask: Vec<_> = df
            .column("service")?
            .utf8()?
            .into_iter()
            .map(|x| x == Some(service))
            .collect();
        let mask = BooleanChunked::new_from_slice("service_mask", &mask);
        df = df.filter(&mask)?;
    }
    if let Some(server) = server {
        let mask: Vec<_> = df
            .column("server")?
            .utf8()?
            .into_iter()
            .map(|x| x == Some(server))
            .collect();
        let mask = BooleanChunked::new_from_slice("server_mask", &mask);
        df = df.filter(&mask)?;
    }
    if let Some(ndays) = ndays {
        let begin_timestamp = naive_datetime_to_datetime(
            &(Utc::now() - Duration::days(i64::from(ndays))).naive_utc(),
        );
        let mask: Vec<_> = df
            .column("datetime")?
            .datetime()?
            .into_iter()
            .map(|x| x.map(|d| d > begin_timestamp))
            .collect();
        let mask = BooleanChunked::new_from_opt_slice("datetime_mask", &mask);
        df = df.filter(&mask)?;
    }
    let df = df.groupby("country")?.select("country").count()?;
    Ok(df)
}

impl AnalysisOpts {
    pub async fn parse_opts() -> Result<(), Error> {
        let default_input = Path::new(
            "/media/seagate4000/dilepton_tower_backup/intrusion_log_backup_20211216.sql.gz",
        )
        .to_path_buf();

        let opts = AnalysisOpts::from_args();
        let config = Config::init_config()?;

        match opts {
            AnalysisOpts::Sync { directory } => {
                let sync = GarminSync::new();
                let directory = directory.unwrap_or_else(|| config.cache_dir.clone());
                println!(
                    "{}",
                    sync.sync_dir("security-log-analysis", &directory, &config.s3_bucket, true,)
                        .await?
                );
            }
            AnalysisOpts::Etl { input, directory } => {
                let input = input.unwrap_or(default_input);
                let directory = directory.unwrap_or_else(|| config.cache_dir.clone());
                read_tsv_file(&input, &directory)?;
            }
            AnalysisOpts::Db { directory } => {
                let directory = directory.unwrap_or_else(|| config.cache_dir.clone());
                let pool = PgPool::new(&config.database_url);
                insert_db_into_parquet(&pool, &directory).await?;
            }
            AnalysisOpts::Read {
                directory,
                service,
                server,
                ndays,
            } => {
                let directory = directory.unwrap_or_else(|| config.cache_dir.clone());
                let service = service.as_ref().map(StackString::as_str);
                let server = server.as_ref().map(StackString::as_str);
                let body = read_parquet_files(&directory, service, server, ndays)?
                    .into_iter()
                    .map(|c| format!("country {} count {}", c.country, c.count))
                    .take(10)
                    .join("\n");
                println!("{}", body);
            }
        }
        Ok(())
    }
}

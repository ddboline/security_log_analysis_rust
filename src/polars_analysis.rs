use anyhow::{format_err, Error};
use chrono::{DateTime, Datelike, Utc};
use flate2::read::GzDecoder;
use itertools::Itertools;
use log::debug;
use polars::prelude::Utf8Chunked;
use postgres_query::{query, FromSqlRow};
use stack_string::StackString;
use std::{
    fs::File,
    io::{BufRead, BufReader, Cursor},
    path::{Path, PathBuf},
};
use structopt::StructOpt;

use polars::{
    chunked_array::builder::NewChunkedArray,
    datatypes::{AnyValue, DataType, DatetimeChunked, Int32Chunked, Int64Chunked, UInt32Chunked},
    frame::DataFrame,
    io::{
        csv::{CsvReader, NullValues},
        parquet::{ParquetReader, ParquetWriter},
        SerReader,
    },
    series::IntoSeries,
};

use security_log_analysis_rust::{config::Config, pgpool::PgPool};

#[derive(StructOpt)]
enum AnalysisOpts {
    Etl {
        #[structopt(short = "i", long = "input")]
        input: Option<PathBuf>,
        #[structopt(short = "d", long = "directory")]
        output: Option<PathBuf>,
    },
    Db {
        #[structopt(short = "d", long = "directory")]
        output: Option<PathBuf>,
    },
    Read {
        #[structopt(short = "i", long = "input")]
        input: Option<PathBuf>,
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
    csv.drop_in_place("datetime_str")?;

    let dt = DatetimeChunked::new_from_naive_datetime("datetime", &v).into_series();
    csv.with_column(dt)?;

    let y: Vec<_> = v.iter().map(Datelike::year).collect();
    let y = Int32Chunked::new_from_slice("year", &y).into_series();
    csv.with_column(y)?;

    let year_group = csv.groupby("year")?;
    let yg = year_group.groups()?;
    for idx in 0..yg.shape().0 {
        if let Some(row) = yg.get(idx) {
            let year = match row.get(0) {
                Some(AnyValue::Int32(y)) => y,
                _ => panic!("Unexpected"),
            };
            let indicies = year_group
                .get_groups()
                .get(idx)
                .unwrap()
                .1
                .iter()
                .map(|i| *i as usize);
            let mut new_csv = csv.take_iter(indicies)?;
            new_csv.drop_in_place("year")?;
            let filename = format!("intrusion_log_{:04}.parquet", year);
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
    struct Wrap(i32);

    #[derive(FromSqlRow)]
    struct IntrusionLogRow {
        id: i32,
        service: StackString,
        server: StackString,
        datetime: DateTime<Utc>,
        host: StackString,
        username: Option<StackString>,
        code: Option<StackString>,
        country: Option<StackString>,
    }

    let query =
        query!("SELECT distinct cast(extract(year from datetime) as int) FROM intrusion_log");
    let conn = pool.get().await?;
    let rows: Vec<Wrap> = query.fetch(&conn).await?;
    for year in rows {
        let year = year.0;
        println!("year {}", year);
        let query = query!(
            r#"
                SELECT a.*, b.code, c.country
                FROM intrusion_log a
                JOIN host_country b ON a.host = b.host
                JOIN country_code c ON b.code = c.code
                WHERE cast(extract(year from datetime at time zone 'utc') as int) = $year
            "#,
            year = year,
        );
        let rows: Vec<IntrusionLogRow> = query.fetch(&conn).await?;

        let mut columns = Vec::new();
        let v: Vec<_> = rows.iter().map(|x| i64::from(x.id)).collect();
        columns.push(Int64Chunked::new_from_slice("id", &v).into_series());
        let v: Vec<_> = rows.iter().map(|x| &x.service).collect();
        columns.push(Utf8Chunked::new_from_slice("service", &v).into_series());
        let v: Vec<_> = rows.iter().map(|x| &x.server).collect();
        columns.push(Utf8Chunked::new_from_slice("server", &v).into_series());
        let v: Vec<_> = rows.iter().map(|x| x.datetime.naive_utc()).collect();
        columns.push(DatetimeChunked::new_from_naive_datetime("datetime", &v).into_series());
        let v: Vec<_> = rows.iter().map(|x| &x.host).collect();
        columns.push(Utf8Chunked::new_from_slice("host", &v).into_series());
        let v: Vec<_> = rows.iter().map(|x| x.username.as_ref()).collect();
        columns.push(Utf8Chunked::new_from_opt_slice("username", &v).into_series());
        let v: Vec<_> = rows.iter().map(|x| x.code.as_ref()).collect();
        columns.push(Utf8Chunked::new_from_opt_slice("code", &v).into_series());
        let v: Vec<_> = rows.iter().map(|x| x.country.as_ref()).collect();
        columns.push(Utf8Chunked::new_from_opt_slice("country", &v).into_series());

        let new_df = DataFrame::new(columns)?;
        println!("{:?}", new_df.shape());

        let filename = format!("intrusion_log_{:04}.parquet", year);
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
    pub code: StackString,
    pub count: u32,
}

fn read_parquet_files(input: &Path) -> Result<Vec<CodeCount>, Error> {
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
    let code: Vec<&str> = Vec::new();
    let code = Utf8Chunked::new_from_slice("code", &code).into_series();
    let code_count = UInt32Chunked::new_from_slice("code_count", &[]).into_series();
    let mut df = DataFrame::new(vec![code, code_count])?;
    for input_file in input_files {
        let new_df = get_code_count(&input_file)?;
        df = df.vstack(&new_df)?;
    }
    let mut df = df.groupby("code")?.sum()?;
    df.rename("code_count_sum", "count")?;
    df.sort_in_place("count", true)?;
    let code_iter = df.column("code")?.utf8()?.into_iter();
    let count_iter = df.column("count")?.u32()?.into_iter();
    let code_count: Vec<_> = code_iter
        .zip(count_iter)
        .filter_map(|(code, count)| {
            code.map(|code| {
                let code = code.into();
                let count = count.unwrap_or(0);
                CodeCount { code, count }
            })
        })
        .collect();
    Ok(code_count)
}

fn get_code_count(input: &Path) -> Result<DataFrame, Error> {
    let df = ParquetReader::new(File::open(&input)?).finish()?;
    println!(
        "{} {:?}",
        input.file_name().unwrap().to_string_lossy(),
        df.shape()
    );
    let df = df.groupby("code")?.select("code").count()?;
    Ok(df)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let default_input =
        Path::new("/media/seagate4000/dilepton_tower_backup/intrusion_log_backup_20211216.sql.gz")
            .to_path_buf();

    let opts = AnalysisOpts::from_args();

    match opts {
        AnalysisOpts::Etl { input, output } => {
            let input = input.unwrap_or(default_input);
            let output = output.unwrap_or_else(|| Path::new(".").to_path_buf());
            read_tsv_file(&input, &output)?;
        }
        AnalysisOpts::Db { output } => {
            let output = output.unwrap_or_else(|| Path::new(".").to_path_buf());
            let config = Config::init_config()?;
            let pool = PgPool::new(&config.database_url);
            insert_db_into_parquet(&pool, &output).await?;
        }
        AnalysisOpts::Read { input } => {
            let input = input.unwrap_or_else(|| Path::new(".").to_path_buf());
            let body = read_parquet_files(&input)?
                .into_iter()
                .map(|c| format!("code {} count {}", c.code, c.count))
                .take(10)
                .join("\n");
            println!("{}", body);
        }
    }
    Ok(())
}

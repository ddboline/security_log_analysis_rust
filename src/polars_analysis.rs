use anyhow::{format_err, Error};
use chrono::{DateTime, Datelike};
use flate2::read::GzDecoder;
use itertools::Itertools;
use log::debug;
use polars::prelude::Utf8Chunked;
use stack_string::StackString;
use std::{
    fs::File,
    io::{BufRead, BufReader, Cursor},
    path::{Path, PathBuf},
};
use structopt::StructOpt;

use polars::{
    chunked_array::builder::NewChunkedArray,
    datatypes::{AnyValue, DataType, DatetimeChunked, UInt32Chunked},
    frame::DataFrame,
    io::{
        csv::{CsvReader, NullValues},
        parquet::{ParquetReader, ParquetWriter},
        SerReader,
    },
    series::IntoSeries,
};

#[derive(StructOpt)]
enum AnalysisOpts {
    Etl {
        #[structopt(short = "i", long = "input")]
        input: Option<PathBuf>,
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
    if buf.len() > 0 {
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

    let dt = DatetimeChunked::new_from_naive_datetime("datetime", &v);
    let dt = dt.into_series();
    csv.with_column(dt)?;

    let y: Vec<_> = v.iter().map(|d| d.year() as u32).collect();
    let y = UInt32Chunked::new_from_slice("year", &y);
    let y = y.into_series();
    csv.with_column(y)?;

    let year_group = csv.groupby("year")?;
    let yg = year_group.groups()?;
    for idx in 0..yg.shape().0 {
        if let Some(row) = yg.get(idx) {
            let year = match row[0] {
                AnyValue::UInt32(y) => y,
                _ => panic!("Unexpected"),
            };
            let indicies: Vec<_> = year_group
                .get_groups()
                .get(idx)
                .unwrap()
                .1
                .iter()
                .map(|i| *i as usize)
                .collect();
            let mut new_csv = csv.take_iter(indicies.into_iter())?;
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
        v?
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
    let df = df.groupby("code")?.select("code").count()?;
    Ok(df)
}

fn main() -> Result<(), Error> {
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
        AnalysisOpts::Read { input } => {
            let input = input.unwrap_or_else(|| Path::new(".").to_path_buf());
            let body = read_parquet_files(&input)?
                .into_iter()
                .map(|c| format!("code {} count {}", c.code, c.count))
                .join("\n");
            println!("{}", body);
        }
    }
    Ok(())
}

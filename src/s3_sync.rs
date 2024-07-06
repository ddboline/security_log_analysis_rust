use anyhow::{format_err, Error};
use aws_config::SdkConfig;
use aws_sdk_s3::{
    operation::list_objects::ListObjectsOutput, primitives::ByteStream, types::Object as S3Object,
    Client as S3Client,
};
use futures::TryStreamExt;
use log::debug;
use rand::{
    distributions::{Alphanumeric, DistString},
    thread_rng,
};
use stack_string::{format_sstr, StackString};
use std::{
    borrow::Borrow,
    convert::{TryFrom, TryInto},
    fs,
    hash::{Hash, Hasher},
    path::Path,
    time::SystemTime,
};
use tokio::{
    fs::File,
    task::{spawn, spawn_blocking, JoinHandle},
};

use crate::{
    exponential_retry, get_md5sum, models::KeyItemCache, pgpool::PgPool,
    polars_analysis::merge_parquet_files,
};

#[derive(Clone)]
pub struct S3Sync {
    s3_client: S3Client,
}

#[derive(Debug, Clone, Eq)]
pub struct KeyItem {
    pub key: StackString,
    pub etag: StackString,
    pub timestamp: i64,
    pub size: u64,
}

impl KeyItem {
    #[must_use]
    fn from_s3_object(mut item: S3Object) -> Option<Self> {
        let key = item.key.take()?.into();
        let etag = item.e_tag.take()?.trim_matches('"').into();
        let timestamp = item.last_modified.as_ref()?.as_secs_f64() as i64;
        let size = item.size? as u64;

        Some(Self {
            key,
            etag,
            timestamp,
            size,
        })
    }
}

impl TryFrom<KeyItem> for KeyItemCache {
    type Error = Error;
    fn try_from(value: KeyItem) -> Result<Self, Self::Error> {
        Ok(Self {
            s3_key: value.key,
            s3_etag: Some(value.etag),
            s3_timestamp: Some(value.timestamp),
            s3_size: Some(value.size.try_into()?),
            ..Self::default()
        })
    }
}

impl PartialEq for KeyItem {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl Hash for KeyItem {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        self.key.hash(state);
    }
}

impl Borrow<str> for &KeyItem {
    fn borrow(&self) -> &str {
        self.key.as_str()
    }
}

impl Default for S3Sync {
    fn default() -> Self {
        let sdk_config = SdkConfig::builder().build();
        Self::new(&sdk_config)
    }
}

impl S3Sync {
    #[must_use]
    pub fn new(sdk_config: &SdkConfig) -> Self {
        Self {
            s3_client: S3Client::from_conf(sdk_config.into()),
        }
    }

    #[must_use]
    pub fn from_client(s3client: S3Client) -> Self {
        Self {
            s3_client: s3client,
        }
    }

    async fn list_keys(
        &self,
        bucket: &str,
        marker: Option<impl AsRef<str>>,
    ) -> Result<ListObjectsOutput, Error> {
        let mut builder = self.s3_client.list_objects().bucket(bucket);
        if let Some(marker) = marker {
            builder = builder.marker(marker.as_ref());
        }
        builder.send().await.map_err(Into::into)
    }

    async fn _get_and_process_keys(&self, bucket: &str, pool: &PgPool) -> Result<usize, Error> {
        let mut marker: Option<String> = None;
        let mut nkeys = 0;
        loop {
            let mut output = self.list_keys(bucket, marker.as_ref()).await?;
            if let Some(contents) = output.contents.take() {
                if let Some(last) = contents.last() {
                    if let Some(key) = last.key() {
                        marker.replace(key.into());
                    }
                }
                for object in contents {
                    if let Some(key) = KeyItem::from_s3_object(object) {
                        if let Some(mut key_item) = KeyItemCache::get_by_key(pool, &key.key).await?
                        {
                            key_item.s3_etag = Some(key.etag);
                            key_item.s3_size = Some(key.size.try_into()?);
                            key_item.s3_timestamp = Some(key.timestamp);

                            if key_item.s3_etag == key_item.local_etag {
                                key_item.do_download = false;
                                key_item.do_upload = false;
                            } else {
                                key_item.do_download = true;
                                key_item.do_upload = true;
                            }
                            key_item.insert(pool).await?;
                        } else {
                            let mut key_item: KeyItemCache = key.try_into()?;
                            key_item.do_download = true;
                            key_item.insert(pool).await?;
                        };
                        nkeys += 1;
                    }
                }
            }
            if output.is_truncated == Some(false) || output.is_truncated.is_none() {
                break;
            }
        }
        Ok(nkeys)
    }

    async fn get_and_process_keys(&self, bucket: &str, pool: &PgPool) -> Result<usize, Error> {
        exponential_retry(|| async move { self._get_and_process_keys(bucket, pool).await }).await
    }

    async fn process_files(&self, local_dir: &Path, pool: &PgPool) -> Result<usize, Error> {
        let mut tasks = Vec::new();
        for dir_line in local_dir.read_dir()? {
            let entry = dir_line?;
            let f = entry.path();
            let metadata = fs::metadata(&f)?;
            let modified: i64 = metadata
                .modified()?
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs()
                .try_into()?;
            let size: i64 = metadata.len().try_into()?;
            if let Some(file_name) = f.file_name() {
                let key: StackString = file_name.to_string_lossy().as_ref().into();
                if let Some(mut key_item) = KeyItemCache::get_by_key(pool, &key).await? {
                    if Some(size) != key_item.local_size {
                        let pool = pool.clone();
                        let task: JoinHandle<Result<(), Error>> = spawn(async move {
                            key_item.local_size = Some(size);
                            let etag = get_md5sum(&f).await?;
                            key_item.local_etag = Some(etag);
                            key_item.local_timestamp = Some(modified);
                            key_item.do_upload = true;
                            key_item.insert(&pool).await?;
                            Ok(())
                        });
                        tasks.push(task);
                    }
                } else {
                    let pool = pool.clone();
                    let task: JoinHandle<Result<(), Error>> = spawn(async move {
                        let etag = get_md5sum(&f).await?;
                        KeyItemCache {
                            s3_key: key,
                            local_etag: Some(etag),
                            local_timestamp: Some(modified),
                            local_size: Some(size),
                            do_upload: true,
                            ..KeyItemCache::default()
                        }
                        .insert(&pool)
                        .await?;
                        Ok(())
                    });
                    tasks.push(task);
                };
            }
        }
        let updates = tasks.len();
        for task in tasks {
            let _ = task.await?;
        }
        Ok(updates)
    }

    /// # Errors
    /// Return error if db query fails
    pub async fn sync_dir(
        &self,
        title: &str,
        local_dir: &Path,
        s3_bucket: &str,
        pool: &PgPool,
    ) -> Result<StackString, Error> {
        let local_updates = self.process_files(local_dir, pool).await?;
        let n_keys = self.get_and_process_keys(s3_bucket, pool).await?;

        let mut number_uploaded = 0;
        let mut number_downloaded = 0;

        let mut stream = Box::pin(KeyItemCache::get_files(pool, Some(true), None).await?);

        while let Some(mut key_item) = stream.try_next().await? {
            let local_file = local_dir.join(&key_item.s3_key);
            self.download_file(&local_file, s3_bucket, &key_item.s3_key)
                .await?;
            number_downloaded += 1;
            let metadata = fs::metadata(&local_file)?;
            let modified: i64 = metadata
                .modified()?
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs()
                .try_into()?;
            key_item.local_etag = Some(get_md5sum(&local_file).await?);
            key_item.local_size = Some(metadata.len().try_into()?);
            key_item.local_timestamp = Some(modified);
            key_item.do_download = false;
            if key_item.s3_etag != key_item.local_etag {
                key_item.do_upload = true;
            }
            key_item.insert(pool).await?;
        }

        let mut stream = Box::pin(KeyItemCache::get_files(pool, None, Some(true)).await?);

        while let Some(mut key_item) = stream.try_next().await? {
            let local_file = local_dir.join(&key_item.s3_key);
            if !local_file.exists() {
                key_item.do_upload = false;
                key_item.insert(pool).await?;
                continue;
            }
            let s3_etag = self
                .upload_file(&local_file, s3_bucket, &key_item.s3_key)
                .await?;
            if Some(&s3_etag) != key_item.local_etag.as_ref() {
                return Err(format_err!("Uploaded etag does not match local"));
            }
            key_item.s3_etag = Some(s3_etag);
            key_item.s3_size = key_item.local_size;
            key_item.s3_timestamp = key_item.local_timestamp;
            number_uploaded += 1;
            key_item.do_upload = false;
            key_item.insert(pool).await?;
        }

        let msg = format_sstr!(
            "{title} {s3_bucket} s3_bucketnkeys {n_keys} updated files {local_updates} uploaded \
             {number_uploaded} downloaded {number_downloaded}",
        );

        Ok(msg)
    }

    /// # Errors
    /// Return error if db query fails
    pub async fn download_file(
        &self,
        local_file: &Path,
        s3_bucket: &str,
        s3_key: &str,
    ) -> Result<StackString, Error> {
        let tmp_path = {
            let mut rng = thread_rng();
            let rand_str = Alphanumeric.sample_string(&mut rng, 8);
            local_file.with_file_name(format_sstr!(".tmp_{rand_str}"))
        };
        let etag: Result<StackString, Error> = exponential_retry(|| {
            let tmp_path = tmp_path.clone();
            async move {
                let resp = self
                    .s3_client
                    .get_object()
                    .bucket(s3_bucket)
                    .key(s3_key)
                    .send()
                    .await?;
                let etag: StackString = resp.e_tag().ok_or_else(|| format_err!("No etag"))?.into();
                tokio::io::copy(
                    &mut resp.body.into_async_read(),
                    &mut File::create(tmp_path).await?,
                )
                .await?;
                Ok(etag)
            }
        })
        .await;
        let output = local_file.to_path_buf();
        debug!("input {tmp_path:?} output {output:?}");
        if output.exists() {
            let input_md5 = get_md5sum(&tmp_path).await?;
            let output_md5 = get_md5sum(&output).await?;
            if input_md5 != output_md5 {
                let result: Result<(), Error> = spawn_blocking(move || {
                    merge_parquet_files(&tmp_path, &output)?;
                    fs::remove_file(&tmp_path).map_err(Into::into)
                })
                .await?;
                result?;
            }
        } else {
            tokio::fs::rename(&tmp_path, &output).await?;
        }
        etag
    }

    /// # Errors
    /// Return error if db query fails
    pub async fn upload_file(
        &self,
        local_file: &Path,
        s3_bucket: &str,
        s3_key: &str,
    ) -> Result<StackString, Error> {
        exponential_retry(|| async move {
            let body = ByteStream::read_from().path(local_file).build().await?;
            let etag = self
                .s3_client
                .put_object()
                .bucket(s3_bucket)
                .key(s3_key)
                .body(body)
                .send()
                .await?
                .e_tag
                .ok_or_else(|| format_err!("Missing etag"))?
                .trim_matches('"')
                .into();
            Ok(etag)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Error;
    use futures::TryStreamExt;

    use crate::{config::Config, models::KeyItemCache, pgpool::PgPool, s3_sync::S3Sync};

    #[tokio::test]
    #[ignore]
    async fn test_process_files_and_keys() -> Result<(), Error> {
        let aws_config = aws_config::load_from_env().await;
        let s3_sync = S3Sync::new(&aws_config);
        let config = Config::init_config()?;
        let pool = PgPool::new(&config.database_url)?;

        s3_sync.process_files(&config.cache_dir, &pool).await?;
        s3_sync
            .get_and_process_keys(&config.s3_bucket, &pool)
            .await?;

        KeyItemCache::get_files(&pool, Some(true), None)
            .await?
            .try_for_each(|key_item| async move {
                println!("upload {}", key_item.s3_key);
                Ok(())
            })
            .await?;

        KeyItemCache::get_files(&pool, None, Some(true))
            .await?
            .try_for_each(|key_item| async move {
                println!("download {}", key_item.s3_key);
                Ok(())
            })
            .await?;
        Ok(())
    }
}

use obfstr::obfstr;

use serde::Serialize;

use colored::Colorize;
use log::{info, debug, trace};
use rayon::prelude::*;

use std::fs;
use std::fs::File;
use std::io::{BufWriter, Cursor, Seek, SeekFrom, Write};
use std::error::Error;

use zip::write::{SimpleFileOptions, ZipWriter};

extern crate zip;
use crate::args::{Options, RUSTHOUND_VERSION};
use crate::objects::common::{Meta, LdapObject};

/// Current Bloodhound version 4.3+
pub const BLOODHOUND_VERSION_4: i8 = 6;

/// Number of objects serialized per parallel batch.
///
/// Objects in a batch are serialized to JSON concurrently (using all CPU
/// cores) then flushed sequentially to the output, so peak extra memory is
/// bounded by one batch instead of the whole dataset.
const SERIALIZE_BATCH: usize = 4096;

/// Where a JSON collection is written: either straight into an entry of the
/// shared zip archive, or into its own `.json` file on disk.
enum Sink<'a> {
    Zip { writer: &'a mut dyn ZipSink, datetime: &'a str, domain: &'a str },
    Dir { path: &'a str, datetime: &'a str, domain: &'a str },
}

trait ZipSink: Write {
    fn start_json_file(&mut self, name: &str) -> zip::result::ZipResult<()>;
}

impl<W: Write + Seek> ZipSink for ZipWriter<W> {
    fn start_json_file(&mut self, name: &str) -> zip::result::ZipResult<()> {
        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .large_file(true);
        self.start_file(name, options)
    }
}

/// Seekable, capacity-limited ZIP storage. The limit is enforced while ZIP
/// entries are written, before an unbounded archive can accumulate in memory.
struct BoundedZipBuffer {
    inner: Cursor<Vec<u8>>,
    max_bytes: usize,
}

impl BoundedZipBuffer {
    fn new(max_bytes: usize) -> Self {
        Self { inner: Cursor::new(Vec::new()), max_bytes }
    }

    fn into_inner(self) -> Vec<u8> {
        self.inner.into_inner()
    }
}

impl Write for BoundedZipBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let end = (self.inner.position() as usize)
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::other("ZIP size overflow"))?;
        if end > self.max_bytes {
            return Err(std::io::Error::other("diskless ZIP size limit exceeded"));
        }
        self.inner.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl Seek for BoundedZipBuffer {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(pos)
    }
}

/// Stream one object collection as a BloodHound JSON document
/// (`{"data":[...],"meta":{...}}`) into `writer`, without ever materialising
/// the whole document (or a `serde_json::Value` DOM) in memory.
///
/// Objects are serialized in parallel batches, which is both faster on
/// many-core machines and keeps memory flat regardless of object count.
fn write_json_document<T, W>(writer: &mut W, name: &str, vec_json: &[T]) -> std::io::Result<()>
where
    T: LdapObject + Serialize + Sync,
    W: Write + ?Sized,
{
    let count = vec_json.len();

    writer.write_all(b"{\"data\":[")?;

    let mut first = true;
    for batch in vec_json.chunks(SERIALIZE_BATCH) {
        // Serialize every object of this batch concurrently across all cores.
        let parts: Vec<String> = batch
            .par_iter()
            .map(|object| serde_json::to_string(object).expect("object serialization failed"))
            .collect();

        for part in parts {
            if !first {
                writer.write_all(b",")?;
            }
            first = false;
            writer.write_all(part.as_bytes())?;
        }
    }

    let meta = Meta::new(
        0_i32,
        name.to_owned(),
        count as i32,
        BLOODHOUND_VERSION_4,
        format!("RustHound-CE v{}", RUSTHOUND_VERSION.to_owned()),
    );
    writer.write_all(b"],\"meta\":")?;
    serde_json::to_writer(&mut *writer, &meta)?;
    writer.write_all(b"}")?;

    Ok(())
}

/// Emit one object collection to the selected [`Sink`]. Empty collections are
/// skipped, matching the previous behaviour (no file/entry is created).
fn emit<T>(sink: &mut Sink, name: &str, vec_json: &[T]) -> Result<(), Box<dyn Error>>
where
    T: LdapObject + Serialize + Sync,
{
    if vec_json.is_empty() {
        return Ok(());
    }

    let count = vec_json.len();
    debug!("Making {name}.json");

    match sink {
        Sink::Zip { writer, datetime, domain } => {
            // `large_file(true)` enables ZIP64, which is required for any entry
            // larger than 4 GiB. Without it the zip crate errors out on huge
            // domains, which is what caused the crash on large outputs.
            // Keep the original entry naming scheme: <datetime>_<domain>_<name>.json
            let filename = format!("{datetime}_{domain}_{name}.json");
            trace!("Adding file {}", filename.bold());
            writer.start_json_file(&filename)?;
            write_json_document(*writer, name, vec_json)?;
        }
        Sink::Dir { path, datetime, domain } => {
            let final_path = format!("{path}/{datetime}_{domain}_{name}.json");
            let file = File::create(&final_path)?;
            let mut buf = BufWriter::new(file);
            write_json_document(&mut buf, name, vec_json)?;
            buf.flush()?;
            info!("{} created!", final_path.bold());
        }
    }

    info!("{} {name} parsed!", count.to_string().bold());
    Ok(())
}

/// Emit every object collection contained in `ad_results` into the given sink.
macro_rules! emit_all {
    ($sink:expr, $ad:expr) => {{
        emit($sink, "users", &$ad.users)?;
        emit($sink, "groups", &$ad.groups)?;
        emit($sink, "computers", &$ad.computers)?;
        emit($sink, "ous", &$ad.ous)?;
        emit($sink, "domains", &$ad.domains)?;
        emit($sink, "gpos", &$ad.gpos)?;
        emit($sink, "containers", &$ad.containers)?;
        emit($sink, "ntauthstores", &$ad.ntauthstores)?;
        emit($sink, "aiacas", &$ad.aiacas)?;
        emit($sink, "rootcas", &$ad.rootcas)?;
        emit($sink, "enterprisecas", &$ad.enterprisecas)?;
        emit($sink, "certtemplates", &$ad.certtemplates)?;
        emit($sink, "issuancepolicies", &$ad.issuancepolicies)?;
    }};
}

/// Write all collections as individual `.json` files on disk.
pub fn write_json_files(
    datetime: &str,
    domain_format: &str,
    common_args: &Options,
    ad_results: &crate::api::ADResults,
) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(&common_args.path)?;
    let mut sink = Sink::Dir {
        path: &common_args.path,
        datetime,
        domain: domain_format,
    };
    emit_all!(&mut sink, ad_results);
    Ok(())
}

/// Stream all collections into a single zip archive.
pub fn make_a_zip(
    datetime: &str,
    domain: &str,
    path: &str,
    ad_results: &crate::api::ADResults,
) -> Result<String, Box<dyn Error>> {
    fs::create_dir_all(path)?;
    let final_path = format!("{path}/{datetime}_{domain}_{}.zip", obfstr!("rusthound-ce"));

    let file = File::create(&final_path)?;
    // A large buffer keeps the single-threaded deflate stream fed and cuts
    // syscall overhead on multi-GB archives.
    let mut writer = ZipWriter::new(BufWriter::with_capacity(1 << 20, file));

    trace!("Making the ZIP file");
    {
        let mut sink = Sink::Zip { writer: &mut writer, datetime, domain };
        emit_all!(&mut sink, ad_results);
    }
    writer.finish()?.flush()?;

    info!("{} created!", &final_path.bold());
    Ok(final_path)
}

/// Produce a BloodHound ZIP without touching the target filesystem.
/// `max_bytes` bounds the archive itself; callers should separately bound the
/// LDAP result set and hold the returned bytes only as long as needed.
pub fn make_zip_bytes(
    datetime: &str,
    domain: &str,
    ad_results: &crate::api::ADResults,
    max_bytes: usize,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut writer = ZipWriter::new(BoundedZipBuffer::new(max_bytes));
    {
        let mut sink = Sink::Zip { writer: &mut writer, datetime, domain };
        emit_all!(&mut sink, ad_results);
    }
    Ok(writer.finish()?.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_zip_is_valid_and_enforces_limit() {
        let mut results = crate::api::ADResults::default();
        results.domains.push(crate::objects::domain::Domain::new());
        let bytes = make_zip_bytes("20261023", "example-local", &results, 1 << 20).unwrap();
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
        assert_eq!(archive.len(), 1);
        assert!(archive.by_index(0).unwrap().name().ends_with("_domains.json"));
        assert!(make_zip_bytes("20261023", "example-local", &results, 64).is_err());
    }
}

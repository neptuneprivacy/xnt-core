pub(crate) mod actor;
pub(crate) mod address_book;
pub(crate) mod ban;
pub(crate) mod bridge;
pub(crate) mod channel;
pub(crate) mod config;
pub(crate) mod gateway;
pub(crate) mod handshake;
pub(crate) mod observed_ips;
pub mod overview;
pub(crate) mod reachability;
pub(crate) mod source_limits;
pub(crate) mod stack;
pub(crate) mod stack_event;

#[cfg(any(test, feature = "arbitrary-impls"))]
pub mod arbitrary;
pub(crate) mod bounce_reason;

use std::fs;
use std::fs::File;
use std::io::BufWriter;
use std::io::Write;
use std::path::Path;

use anyhow::Context;

/// Write the value as JSON to the file at `path`, replacing the file
/// atomically.
///
/// The JSON is written to a temporary file in the same directory, which is
/// synced to disk and then renamed to `path`. A reader thus finds either the
/// previous contents or the new ones, never a partly written file, even if the
/// node stops while writing.
pub(crate) fn save_json_atomically<T: serde::Serialize + ?Sized>(
    path: &Path,
    value: &T,
) -> anyhow::Result<()> {
    let file_name = path
        .file_name()
        .with_context(|| format!("`{}` names no file", path.display()))?;
    let mut temporary_file_name = file_name.to_os_string();
    temporary_file_name.push(".tmp");
    let temporary_path = path.with_file_name(temporary_file_name);
    if let Some(directory) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(directory)?;
    }

    let mut writer = BufWriter::new(File::create(&temporary_path)?);
    serde_json::to_writer_pretty(&mut writer, value)?;
    writer.flush()?;
    writer.get_ref().sync_all()?;
    drop(writer);
    fs::rename(&temporary_path, path)?;

    // Make the rename itself durable.
    #[cfg(unix)]
    if let Some(directory) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        File::open(directory)?.sync_all()?;
    }

    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn json_is_saved_atomically_and_replaces_the_file() {
        let directory = std::env::temp_dir().join(format!(
            "save_json_atomically_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let path = directory.join("list.json");

        let first = HashMap::from([("a".to_string(), 1)]);
        save_json_atomically(&path, &first).unwrap();
        let second = HashMap::from([("b".to_string(), 2)]);
        save_json_atomically(&path, &second).unwrap();

        let saved: HashMap<String, i32> =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(second, saved);
        let file_names = fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(vec![std::ffi::OsString::from("list.json")], file_names);

        let _ = fs::remove_dir_all(&directory);
    }
}

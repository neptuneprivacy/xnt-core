use std::fs;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use anyhow::Context;
use anyhow::Result;
use libp2p::identity::Keypair;
use tracing::info;

const IDENTITY_WARNING_HEADER: &str = r#"# =============================================================================
# LIBP2P NODE IDENTITY KEY
# =============================================================================
# This file contains the private key for your P2P node identity.
#
# WHAT IT DOES:
# - Manages your node's PeerId and network identity.
# - Allows other peers to recognize you across restarts.
#
# WHAT IT DOES NOT DO:
# - It DOES NOT manage, store, or protect any cryptocurrency funds.
# =============================================================================
"#;

/// Read the node's libp2p identity from the filesystem or generate a new one.
///
/// Two workflows are supported:
///
///  1. **Persistent Identity (Default)**
///     The identity is read from `identity_filename`, and generated and
///     written there if the file does not exist. The node thereby keeps its
///     standing and reachability in the Kademlia DHT and the relay service
///     across restarts.
///
///  2. **Identity Rotation (`new_identity: true`)**
///     Forces the generation of a fresh identity while preserving the old one.
///     The existing file is renamed to `<name>.<timestamp>.bak`.
///
/// The identity file contains a human-readable header explaining that this key
/// manages **network identity only** and does not control **cryptocurrency
/// funds**. The key material itself is stored as a hex-encoded
/// Protobuf-serialized Ed25519 keypair. On Unix, a new file is readable and
/// writable by its owner only.
///
/// # Return Value
///
///  - Err(_) if some crucial file system or codec operation failed.
///  - Ok(KeyPair) otherwise.
///
/// Falling back on an ephemeral identity in the event of a file system or
/// codec failure is the caller's responsibility.
pub(crate) fn resolve_identity(identity_filename: PathBuf, new_identity: bool) -> Result<Keypair> {
    // New Identity: rotate existing file with timestamped backup
    if new_identity && identity_filename.exists() {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let backup = identity_filename.with_extension(format!("{}.bak", ts));
        fs::rename(&identity_filename, &backup).context("Failed to backup identity")?;
        info!(
            "Backed up existing identity file to '{}'.",
            backup.to_string_lossy()
        );
        info!(
            "Proceeding with fresh new identity at '{}'.",
            identity_filename.to_string_lossy()
        );
    }

    // Load or create identity
    if identity_filename.exists() {
        let content =
            fs::read_to_string(&identity_filename).context("Failed to read identity file")?;
        let encoded_key = content
            .lines()
            .find(|line| !line.trim().starts_with('#') && !line.trim().is_empty())
            .context("No key data found")?;

        let bytes = hex::decode(encoded_key.trim()).context("Failed to decode hex key")?;
        let keypair =
            Keypair::from_protobuf_encoding(&bytes).context("Failed to parse protobuf key");

        info!(
            "Using identity file '{}'.",
            identity_filename.to_string_lossy()
        );

        keypair
    } else {
        info!("Generating new persistent identity.");
        if let Some(parent) = identity_filename.parent() {
            fs::create_dir_all(parent).context("Create identity directory")?;
        }

        let new_key = Keypair::generate_ed25519();
        let bytes = new_key
            .to_protobuf_encoding()
            .context("Failed to encode key")?;
        let file_content = format!("{}\n{}", IDENTITY_WARNING_HEADER, hex::encode(bytes));

        write_owner_only(&identity_filename, file_content.as_bytes())
            .context("Failed to save identity file")?;
        info!(
            "Saved new identity file to '{}'.",
            identity_filename.to_string_lossy()
        );
        Ok(new_key)
    }
}

/// Write the contents to a new file. On Unix, the file is created with mode
/// `0600`, so that only its owner can read or write it.
fn write_owner_only(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::env;

    use super::*;

    fn test_dir(name: &str) -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut data_dir = env::temp_dir();
        data_dir.push(format!("{name}_{ts}_{}", std::process::id()));
        data_dir
    }

    #[test]
    fn test_identity_lifecycle() {
        let data_dir = test_dir("identity_test");
        let filename = data_dir.join("identity.key");

        fs::create_dir_all(&data_dir).expect("Failed to create test temp dir");

        // --- Test 1: Initial Generation ---
        let key1 = resolve_identity(filename.clone(), false).expect("Should generate new identity");
        let id1 = key1.public().to_peer_id();

        // --- Test 2: Persistence (Load existing) ---
        let key2 =
            resolve_identity(filename.clone(), false).expect("Should load existing identity");
        assert_eq!(
            id1,
            key2.public().to_peer_id(),
            "Identity should be persistent"
        );

        // --- Test 3: New Identity (Backup and rotate) ---
        let key_new = resolve_identity(filename.clone(), true).expect("Should back up identity");
        assert_ne!(
            id1,
            key_new.public().to_peer_id(),
            "New identity should be different"
        );

        // Verify backup file exists
        let has_backup = fs::read_dir(&data_dir)
            .unwrap()
            .map(|res| res.unwrap().path())
            .any(|path| {
                path.extension()
                    .is_some_and(|ext| ext.to_string_lossy().contains("bak"))
            });
        assert!(has_backup, "Backup file should exist after backing up");

        // Cleanup
        let _ = fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn missing_parent_directories_are_created() {
        let data_dir = test_dir("identity_parent_test");
        let filename = data_dir.join("network").join("identity.key");

        let key = resolve_identity(filename.clone(), false).unwrap();
        assert!(filename.exists());
        assert_eq!(
            key.public().to_peer_id(),
            resolve_identity(filename, false)
                .unwrap()
                .public()
                .to_peer_id()
        );

        let _ = fs::remove_dir_all(&data_dir);
    }

    #[cfg(unix)]
    #[test]
    fn new_identity_file_is_readable_by_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let data_dir = test_dir("identity_mode_test");
        let filename = data_dir.join("identity.key");
        fs::create_dir_all(&data_dir).unwrap();

        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;

        resolve_identity(filename.clone(), false).unwrap();
        assert_eq!(0o600, mode(&filename), "mode was {:o}", mode(&filename));

        // A rotated identity is written with the same mode.
        resolve_identity(filename.clone(), true).unwrap();
        assert_eq!(0o600, mode(&filename), "mode was {:o}", mode(&filename));

        let _ = fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn corrupt_identity_file_is_an_error_and_is_left_as_it_is() {
        let data_dir = test_dir("identity_corrupt_test");
        let filename = data_dir.join("identity.key");
        fs::create_dir_all(&data_dir).unwrap();

        for corrupt in [
            format!("{IDENTITY_WARNING_HEADER}\nnot hex"),
            IDENTITY_WARNING_HEADER.to_string(),
        ] {
            fs::write(&filename, &corrupt).unwrap();
            assert!(resolve_identity(filename.clone(), false).is_err());
            assert_eq!(corrupt, fs::read_to_string(&filename).unwrap());
        }

        let _ = fs::remove_dir_all(&data_dir);
    }
}

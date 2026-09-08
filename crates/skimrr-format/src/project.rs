use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// The longest relative path a container may name. Well past anything a real photo
/// library produces, and short enough that a million of them cannot be used to exhaust
/// memory on their own.
pub const MAX_PATH_LEN: usize = 1024;

/// What a project is.
///
/// Skimrr had no such thing before this format: a scan lived in memory and died with
/// the application, and the only thing on disk was a per-file analysis cache keyed by
/// absolute path. A project is what that scan becomes when it has to survive being
/// carried to another machine — so it records what was looked at, what was found, and
/// what the user decided, and it does so without depending on where the files were.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Project {
    /// Free-form, shown to the person opening it. Never used as a filename.
    pub name: String,
    /// Seconds since the Unix epoch. Informational only; nothing branches on it.
    pub created: i64,
    pub settings: Settings,
    /// The folders the scan was given, as they were named on the machine that made the
    /// project. Kept only as a hint for relocation — never opened, never trusted.
    pub roots: Vec<String>,
    pub entries: Vec<Entry>,
    /// Duplicate groups, as indices into `entries`.
    pub groups: Vec<Group>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    pub similarity_threshold: u32,
    pub blur_threshold: f64,
    pub face_threshold: f64,
}

/// One photograph, identified by what it *is* rather than by where it was.
///
/// `path` is relative to the root it was found under, so a project made on Windows
/// opens on Linux; `sha` and `phash` are what actually identify the file when the paths
/// no longer line up, which on another machine they never do.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    /// Which of `roots` this was found under.
    pub root: u32,
    /// Path below that root, always with `/` separators whatever wrote it.
    pub path: String,
    pub size: u64,
    /// SHA-256 of the file, when the scan computed one. The strong identifier: two
    /// files with the same digest are the same file, wherever they sit.
    #[serde(default)]
    pub sha: Option<String>,
    /// The 128-bit perceptual fingerprint. Survives a re-encode, so it can still match
    /// a copy that a transfer has quietly recompressed.
    #[serde(default)]
    pub phash: Option<String>,
    pub taken: i64,
    #[serde(default)]
    pub blur: Option<f64>,
    /// The Bad Shot verdict, carried as opaque CBOR so this crate does not have to
    /// track every field the application adds to it.
    #[serde(default)]
    pub bad_shot: Option<ciborium::Value>,
    /// Everything else the application knows about this photograph — dimensions, camera,
    /// coordinates — carried opaquely for the same reason.
    ///
    /// The format deliberately does not model any of it. A container is data and only
    /// data; this crate's job is to get those bytes across a machine boundary intact and
    /// prove they were not altered on the way, not to have an opinion about what a
    /// photograph is. It also means the application can add a field without the format
    /// changing version.
    #[serde(default)]
    pub extra: Option<ciborium::Value>,
    /// Whether the user had chosen this one to keep.
    #[serde(default)]
    pub kept: bool,
    /// Index into the container's blobs, when a thumbnail or the original travelled
    /// with the project.
    #[serde(default)]
    pub thumbnail: Option<u32>,
    #[serde(default)]
    pub original: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Group {
    pub members: Vec<u32>,
    pub suggested: u32,
    pub kind: String,
}

/// Whether a path from a container may be used to build a real filename.
///
/// A `.skimrr` is untrusted input, and this is the function that stops it writing
/// outside the folder it was extracted into. Every rule below corresponds to a real
/// escape: `..` walks upward, a leading separator or a drive letter escapes sideways,
/// a NUL truncates the name for a C API further down, and a backslash is a separator on
/// one platform and a legal filename character on another — which is precisely how a
/// path that looks safe on Linux becomes `..\..\` on Windows.
pub fn safe_relative_path(path: &str) -> Result<()> {
    if path.is_empty() || path.len() > MAX_PATH_LEN {
        return Err(Error::UnsafePath);
    }
    if path.contains('\0') || path.contains('\\') {
        return Err(Error::UnsafePath);
    }
    // Absolute in the POSIX sense, or a Windows drive or UNC path.
    if path.starts_with('/') {
        return Err(Error::UnsafePath);
    }
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        return Err(Error::UnsafePath);
    }

    for component in path.split('/') {
        // An empty component is a doubled separator or a trailing one; either way the
        // path is not the plain relative name it claims to be.
        if component.is_empty() || component == "." || component == ".." {
            return Err(Error::UnsafePath);
        }
        // Windows resolves these to devices wherever they appear, extension or not, and
        // will happily open one instead of a file.
        let stem = component.split('.').next().unwrap_or(component).to_ascii_uppercase();
        const DEVICES: [&str; 22] = [
            "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
            "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        ];
        if DEVICES.contains(&stem.as_str()) {
            return Err(Error::UnsafePath);
        }
        // Trailing dots and spaces are silently stripped by Windows, so two distinct
        // names in the manifest can become one file on disk.
        if component.ends_with('.') || component.ends_with(' ') {
            return Err(Error::UnsafePath);
        }
    }
    Ok(())
}

impl Project {
    /// Checks a freshly parsed project against the container that carried it.
    ///
    /// Runs before anything is shown or written. The manifest is attacker-controlled
    /// even when the cryptography passes — a valid signature over hostile data is still
    /// hostile data — so every index it contains is checked against what actually
    /// exists rather than trusted to be in range.
    pub fn validate(&self, blob_count: u32) -> Result<()> {
        if self.roots.is_empty() && !self.entries.is_empty() {
            return Err(Error::MalformedManifest);
        }
        let mut seen_blobs = alloc_set(blob_count);

        for entry in &self.entries {
            safe_relative_path(&entry.path)?;
            if entry.root as usize >= self.roots.len() {
                return Err(Error::MalformedManifest);
            }
            for blob in [entry.thumbnail, entry.original].into_iter().flatten() {
                if blob >= blob_count {
                    return Err(Error::MalformedManifest);
                }
                // One blob, one owner. A manifest pointing two entries at the same
                // payload is either a mistake or an attempt to make the reader's
                // accounting disagree with the file's.
                if seen_blobs[blob as usize] {
                    return Err(Error::MalformedManifest);
                }
                seen_blobs[blob as usize] = true;
            }
        }

        let n = self.entries.len() as u32;
        for group in &self.groups {
            if group.members.is_empty() || group.suggested as usize >= group.members.len() {
                return Err(Error::MalformedManifest);
            }
            for &m in &group.members {
                if m >= n {
                    return Err(Error::MalformedManifest);
                }
            }
        }
        Ok(())
    }
}

fn alloc_set(n: u32) -> Vec<bool> {
    vec![false; n as usize]
}

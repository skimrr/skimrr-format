use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Eight bytes that say "this is a Skimrr project".
///
/// The `0x1A` is deliberate: it is the DOS end-of-file character, so a container piped
/// into a text tool stops there instead of spraying binary at a terminal. The trailing
/// `0x00` keeps the magic from ever being valid UTF-8 text a user might paste.
pub const MAGIC: [u8; 8] = *b"SKIMRR\x1A\x00";

/// The container layout this build writes, and the highest it can read.
///
/// A reader must refuse anything higher rather than guess: a future version may move
/// fields, and a hopeful parse of a layout it does not know is exactly how a format
/// starts silently corrupting projects.
pub const FORMAT_VERSION: u16 = 1;

/// Bytes of header CBOR. Generous for a structure of a dozen fields, and small enough
/// that a hostile file cannot make the reader allocate anything meaningful before a
/// single field has been validated.
pub const MAX_HEADER_LEN: u32 = 64 * 1024;

/// Ceilings every declared length is checked against before it is used to allocate.
/// None of them constrain a real project; all of them stop a four-byte edit turning
/// into a multi-gigabyte allocation.
pub const MAX_MANIFEST_LEN: u64 = 256 * 1024 * 1024;
pub const MAX_BLOBS: u32 = 2_000_000;
pub const MAX_BODY_LEN: u64 = 2 * 1024 * 1024 * 1024 * 1024; // 2 TiB
pub const MAX_FRAME_LEN: u32 = 16 * 1024 * 1024;

bitflags_lite! {
    /// What the container holds. Read before anything is decrypted, so the reader can
    /// say "this needs a password" without one.
    pub struct Flags: u32 {
        const ENCRYPTED   = 1 << 0;
        const THUMBNAILS  = 1 << 1;
        const ORIGINALS   = 1 << 2;
    }
}

/// How the payload was compressed. Only the manifest and thumbnails are compressed;
/// originals never are, being JPEG or HEIC already.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Compression {
    None = 0,
    Deflate = 1,
}

/// The key derivation, recorded so a future build can raise the cost without orphaning
/// the projects written today. Absent on an unencrypted container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Kdf {
    /// Only Argon2id is defined; the field exists so a successor can be added.
    pub algorithm: u8,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
    #[serde(with = "crate::serde_bytes_array16")]
    pub salt: [u8; 16],
    /// STREAM spends five of XChaCha20's twenty-four nonce bytes on its frame counter
    /// and last-frame flag, so nineteen are stored.
    #[serde(with = "crate::serde_bytes_array19")]
    pub nonce: [u8; 19],
}

pub const ARGON2ID: u8 = 1;

/// Everything a reader needs before it can touch the body.
///
/// Written in the clear — a reader has to know a file is encrypted before it can ask
/// for a password — but fed to the cipher as associated data, so any edit to it makes
/// every frame fail to authenticate. On an unencrypted container there is no key and
/// therefore no authenticity to be had; `digest` gives integrity against damage, which
/// is a different and weaker promise, and the documentation says so plainly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub flags: u32,
    pub compression: Compression,
    pub kdf: Option<Kdf>,
    /// Plaintext bytes per sealed frame.
    pub frame_len: u32,
    /// Length of the compressed manifest inside the body.
    pub manifest_len: u64,
    /// How many blobs follow the manifest.
    pub blob_count: u32,
    /// Total plaintext length of the body, manifest and blobs together.
    pub body_len: u64,
    /// SHA-256 of the plaintext body. Only meaningful on an unencrypted container;
    /// when the body is sealed, the AEAD tag is the real check and this is ignored.
    #[serde(with = "crate::serde_bytes_array32")]
    pub digest: [u8; 32],
}

impl Header {
    pub fn flags(&self) -> Flags {
        Flags::from_bits_truncate(self.flags)
    }

    pub fn encrypted(&self) -> bool {
        self.flags().contains(Flags::ENCRYPTED)
    }

    /// Rejects any header that cannot describe a real container.
    ///
    /// Every check here exists because the alternative is acting on a number an
    /// attacker chose: allocating from `manifest_len`, looping `blob_count` times, or
    /// deriving a key from parameters that would exhaust memory.
    pub fn validate(&self) -> Result<()> {
        let flags = Flags::from_bits(self.flags).ok_or(Error::MalformedHeader("unknown flag"))?;

        match (&self.kdf, flags.contains(Flags::ENCRYPTED)) {
            (Some(_), false) => {
                return Err(Error::MalformedHeader("key derivation on a plain container"))
            }
            (None, true) => {
                return Err(Error::MalformedHeader("encrypted with no key derivation"))
            }
            _ => {}
        }

        if let Some(kdf) = &self.kdf {
            if kdf.algorithm != ARGON2ID {
                return Err(Error::MalformedHeader("unknown key derivation"));
            }
            // Below the floor a password would be brute-forceable; above the ceiling a
            // file could make the reader allocate a gigabyte before it can refuse.
            if kdf.m_kib < 8 * 1024 || kdf.m_kib > 1024 * 1024 {
                return Err(Error::MalformedHeader("implausible memory cost"));
            }
            if kdf.t == 0 || kdf.t > 16 || kdf.p == 0 || kdf.p > 8 {
                return Err(Error::MalformedHeader("implausible time or parallelism cost"));
            }
        }

        if self.frame_len == 0 || self.frame_len > MAX_FRAME_LEN {
            return Err(Error::MalformedHeader("implausible frame length"));
        }
        if self.manifest_len == 0 || self.manifest_len > MAX_MANIFEST_LEN {
            return Err(Error::TooLarge { limit: MAX_MANIFEST_LEN });
        }
        if self.blob_count > MAX_BLOBS {
            return Err(Error::TooLarge { limit: MAX_BLOBS as u64 });
        }
        if self.body_len > MAX_BODY_LEN {
            return Err(Error::TooLarge { limit: MAX_BODY_LEN });
        }
        // The manifest lives inside the body, after its own eight-byte length.
        if self.manifest_len.saturating_add(8) > self.body_len {
            return Err(Error::MalformedHeader("manifest longer than the body holding it"));
        }
        Ok(())
    }
}

/// The bytes a container opens with: magic, version, header length, header.
///
/// Returned as one slice because that is exactly what is fed to the cipher as
/// associated data. Building it once and using it for both purposes is what makes it
/// impossible for the authenticated bytes and the parsed bytes to drift apart.
pub fn encode(header: &Header) -> Result<Vec<u8>> {
    let mut cbor = Vec::new();
    ciborium::into_writer(header, &mut cbor).map_err(|_| Error::MalformedManifest)?;
    if cbor.len() as u32 > MAX_HEADER_LEN {
        return Err(Error::TooLarge { limit: MAX_HEADER_LEN as u64 });
    }
    let mut out = Vec::with_capacity(14 + cbor.len());
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&(cbor.len() as u32).to_le_bytes());
    out.extend_from_slice(&cbor);
    Ok(out)
}

/// Parses the opening bytes, returning the header and how many bytes it occupied.
///
/// Checks in the order a hostile file makes necessary: magic first, then version, then
/// the declared length against a ceiling, and only then is any of it deserialised.
pub fn decode(bytes: &[u8]) -> Result<(Header, usize)> {
    if bytes.len() < 14 {
        return Err(Error::NotSkimrr);
    }
    if bytes[..8] != MAGIC {
        return Err(Error::NotSkimrr);
    }
    let version = u16::from_le_bytes([bytes[8], bytes[9]]);
    if version == 0 || version > FORMAT_VERSION {
        return Err(Error::UnsupportedVersion { found: version, supported: FORMAT_VERSION });
    }
    let len = u32::from_le_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]);
    if len == 0 || len > MAX_HEADER_LEN {
        return Err(Error::MalformedHeader("implausible header length"));
    }
    let end = 14usize
        .checked_add(len as usize)
        .ok_or(Error::MalformedHeader("header length overflows"))?;
    if bytes.len() < end {
        return Err(Error::MalformedHeader("truncated before the header ends"));
    }
    let header: Header =
        ciborium::from_reader(&bytes[14..end]).map_err(|_| Error::MalformedHeader("undecodable"))?;
    header.validate()?;
    Ok((header, end))
}

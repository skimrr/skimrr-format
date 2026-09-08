use crate::crypto::{self, Profile, TAG_LEN};
use crate::error::{Error, Result};
use crate::header::{self, Compression, Flags, Header, MAX_BLOBS, MAX_MANIFEST_LEN};
use crate::project::Project;

/// Plaintext bytes per sealed frame.
///
/// A megabyte is small enough that opening a twenty-gigabyte project never needs more
/// than a megabyte of working memory, and large enough that the sixteen-byte tag on
/// each frame costs sixteen parts in a million rather than anything worth counting.
pub const FRAME_LEN: u32 = 1024 * 1024;

/// The most a manifest may expand to once decompressed. A compressed manifest is
/// capped in the header; this caps what it may become, which is the other half of the
/// same problem — a few kilobytes of deflate can otherwise ask for gigabytes.
const MAX_MANIFEST_PLAIN: usize = 512 * 1024 * 1024;

/// What travels with the project besides the project itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Contents {
    pub thumbnails: bool,
    pub originals: bool,
}

/// A container that has been read, authenticated and validated.
#[derive(Debug, Clone, PartialEq)]
pub struct Opened {
    pub header: Header,
    pub project: Project,
    /// Blob payloads in manifest order. Empty when the container carried none.
    pub blobs: Vec<Vec<u8>>,
}

/// Reads only the opening bytes, so a caller can tell whether a password is needed
/// before asking for one — and can show what the file holds without holding the key.
pub fn peek(bytes: &[u8]) -> Result<Header> {
    header::decode(bytes).map(|(h, _)| h)
}

/// Writes a complete container.
///
/// `blobs` are referenced by index from the manifest; the caller has already decided
/// which entries own which, and `Project::validate` will refuse a manifest whose
/// indices do not line up with what is actually here.
pub fn write(
    project: &Project,
    blobs: &[Vec<u8>],
    contents: Contents,
    password: Option<&str>,
    profile: Profile,
) -> Result<Vec<u8>> {
    if blobs.len() as u64 > MAX_BLOBS as u64 {
        return Err(Error::TooLarge { limit: MAX_BLOBS as u64 });
    }
    project.validate(blobs.len() as u32)?;

    // The manifest is text-like and compresses well; the blobs are JPEG or HEIC and do
    // not, so they are stored. Compressing them again would cost time to gain nothing.
    let mut cbor = Vec::new();
    ciborium::into_writer(project, &mut cbor).map_err(|_| Error::MalformedManifest)?;
    let manifest = miniz_oxide::deflate::compress_to_vec(&cbor, 6);
    if manifest.len() as u64 > MAX_MANIFEST_LEN {
        return Err(Error::TooLarge { limit: MAX_MANIFEST_LEN });
    }

    let mut body = Vec::new();
    body.extend_from_slice(&(manifest.len() as u64).to_le_bytes());
    body.extend_from_slice(&manifest);
    for blob in blobs {
        body.extend_from_slice(&(blob.len() as u64).to_le_bytes());
        body.extend_from_slice(blob);
    }

    let mut flags = Flags(0);
    if contents.thumbnails {
        flags = flags | Flags::THUMBNAILS;
    }
    if contents.originals {
        flags = flags | Flags::ORIGINALS;
    }
    let kdf = match password {
        Some(_) => {
            flags = flags | Flags::ENCRYPTED;
            Some(profile.new_kdf())
        }
        None => None,
    };

    let head = Header {
        flags: flags.bits(),
        compression: Compression::Deflate,
        kdf: kdf.clone(),
        frame_len: FRAME_LEN,
        manifest_len: manifest.len() as u64,
        blob_count: blobs.len() as u32,
        body_len: body.len() as u64,
        digest: crypto::digest(&body),
    };
    head.validate()?;
    let prefix = header::encode(&head)?;

    let mut out = prefix.clone();
    match (password, &kdf) {
        (Some(password), Some(kdf)) => {
            let key = crypto::derive_key(password, kdf)?;
            // The whole header — magic, version, length and all — is the associated
            // data, so there is no field of it an editor can touch without every frame
            // failing to open.
            let mut sealer = crypto::Sealer::new(&key, kdf, prefix);
            let count = body.chunks(FRAME_LEN as usize).count();
            // The body always carries at least the manifest and its length, so this
            // cannot happen; the reader still checks the same thing on the way back in,
            // where it is a hostile file rather than a bug.
            if count == 0 {
                return Err(Error::MalformedBody("a project cannot be empty"));
            }
            for (i, chunk) in body.chunks(FRAME_LEN as usize).enumerate() {
                if i + 1 == count {
                    out.extend_from_slice(&sealer.last(chunk)?);
                    break;
                }
                out.extend_from_slice(&sealer.frame(chunk)?);
            }
        }
        _ => out.extend_from_slice(&body),
    }
    Ok(out)
}

/// Reads a container, authenticating it before believing any of it.
///
/// The order matters and is deliberate: parse and bound-check the header, derive the
/// key, authenticate every frame, only then decompress, only then deserialise, and only
/// then validate the manifest's own indices. Nothing attacker-controlled is acted upon
/// before the step that could reject it has run.
pub fn read(bytes: &[u8], password: Option<&str>) -> Result<Opened> {
    let (head, offset) = header::decode(bytes)?;
    let rest = &bytes[offset..];

    let body = if head.encrypted() {
        let kdf = head.kdf.as_ref().ok_or(Error::MalformedHeader("encrypted with no kdf"))?;
        let password = password.ok_or(Error::WrongPasswordOrTampered)?;

        /* Frame boundaries are computed from the header, never read from the body.
           That is what makes "falsify a frame length" impossible rather than merely
           detectable: there is no length field to falsify, and the header the sizes
           come from is itself authenticated as associated data. */
        let frames_declared = head.body_len.div_ceil(head.frame_len as u64);
        if frames_declared == 0 {
            return Err(Error::MalformedBody("a sealed body cannot be empty"));
        }
        // All of this arithmetic stays in `u64` until the length check has passed.
        // `usize` is 32 bits in WebAssembly, and a header is free to declare a two-
        // terabyte body in one-byte frames — casting first would truncate the count and
        // let a wrapped product agree with a short file.
        let expected = frames_declared
            .checked_mul(TAG_LEN as u64)
            .and_then(|tags| head.body_len.checked_add(tags))
            .ok_or(Error::MalformedBody("the declared body overflows"))?;
        // Exactly, in both directions: short means truncated, long means something was
        // appended — an extra frame, or padding meant to be ignored.
        if rest.len() as u64 != expected {
            return Err(Error::MalformedBody(
                "the sealed body is not the length the header declares",
            ));
        }
        // Past that check every one of these fits: the file is genuinely `expected`
        // bytes long, so the frame count and the body length are both bounded by a
        // slice this machine is already holding.
        let frame_len = head.frame_len as usize;
        let frames = frames_declared as usize;

        let key = crypto::derive_key(password, kdf)?;
        let mut opener = crypto::Opener::new(&key, kdf, bytes[..offset].to_vec());
        let mut body = Vec::with_capacity(head.body_len.min(64 * 1024 * 1024) as usize);
        let mut cursor = 0usize;
        for i in 0..frames {
            let plain_len = if i + 1 == frames {
                (head.body_len as usize) - i * frame_len
            } else {
                frame_len
            };
            let sealed = &rest[cursor..cursor + plain_len + TAG_LEN];
            cursor += plain_len + TAG_LEN;
            let plain = if i + 1 == frames {
                let last = core::mem::replace(
                    &mut opener,
                    crypto::Opener::new(&key, kdf, Vec::new()),
                );
                last.last(sealed)?
            } else {
                opener.frame(sealed)?
            };
            body.extend_from_slice(&plain);
        }
        body
    } else {
        if rest.len() as u64 != head.body_len {
            return Err(Error::MalformedBody("the body is not the length the header declares"));
        }
        // No key means no authenticity, only integrity: this catches damage, not an
        // edit by someone who also recomputed the digest. Documented as such.
        if crypto::digest(rest) != head.digest {
            return Err(Error::Corrupted);
        }
        rest.to_vec()
    };

    // From here the bytes are authenticated, but they are still whatever the writer
    // chose to put there, so every offset is still checked.
    let mut cursor = 0usize;
    let manifest_len = read_u64(&body, &mut cursor)? as usize;
    if manifest_len as u64 != head.manifest_len {
        return Err(Error::MalformedBody("manifest length disagrees with the header"));
    }
    let manifest = slice(&body, &mut cursor, manifest_len)?;
    let cbor = match head.compression {
        Compression::Deflate => {
            miniz_oxide::inflate::decompress_to_vec_with_limit(manifest, MAX_MANIFEST_PLAIN)
                .map_err(|_| Error::MalformedManifest)?
        }
        Compression::None => manifest.to_vec(),
    };
    let project: Project =
        ciborium::from_reader(cbor.as_slice()).map_err(|_| Error::MalformedManifest)?;

    let mut blobs = Vec::with_capacity(head.blob_count.min(4096) as usize);
    for _ in 0..head.blob_count {
        let len = read_u64(&body, &mut cursor)? as usize;
        blobs.push(slice(&body, &mut cursor, len)?.to_vec());
    }
    if cursor != body.len() {
        return Err(Error::MalformedBody("trailing data after the last blob"));
    }

    project.validate(head.blob_count)?;
    Ok(Opened { header: head, project, blobs })
}

fn read_u64(body: &[u8], cursor: &mut usize) -> Result<u64> {
    let end = cursor.checked_add(8).ok_or(Error::MalformedBody("offset overflows"))?;
    if end > body.len() {
        return Err(Error::MalformedBody("truncated where a length was expected"));
    }
    let v = u64::from_le_bytes(body[*cursor..end].try_into().unwrap());
    *cursor = end;
    Ok(v)
}

fn slice<'a>(body: &'a [u8], cursor: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = cursor.checked_add(len).ok_or(Error::MalformedBody("offset overflows"))?;
    if end > body.len() {
        return Err(Error::MalformedBody("a declared length runs past the end"));
    }
    let s = &body[*cursor..end];
    *cursor = end;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{
        Kdf, ARGON2ID, FORMAT_VERSION, MAGIC, MAX_BLOBS, MAX_BODY_LEN, MAX_FRAME_LEN,
        MAX_MANIFEST_LEN,
    };
    use crate::project::{Entry, Group, Project, Settings};

    const PW: &str = "correct horse battery staple";

    // ------------------------------------------------------------------ fixtures

    /// Deterministic pseudo-random filler. Real photographs do not compress, and neither
    /// does this, so a multi-frame test is honest about how big its body actually gets.
    fn noise(seed: u64, len: usize) -> Vec<u8> {
        let mut s = seed | 1;
        (0..len)
            .map(|_| {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                (s >> 24) as u8
            })
            .collect()
    }

    fn entry(path: &str) -> Entry {
        Entry {
            root: 0,
            path: path.into(),
            size: 4_812_003,
            sha: Some("ab".repeat(32)),
            phash: Some("0f1e2d3c4b5a6978".into()),
            taken: 1_700_000_000,
            blur: Some(87.25),
            bad_shot: None,
            extra: None,
            kept: true,
            thumbnail: None,
            original: None,
        }
    }

    fn project(paths: &[&str]) -> Project {
        Project {
            name: "Été 2024 — Corse".into(),
            created: 1_700_000_000,
            settings: Settings {
                similarity_threshold: 10,
                blur_threshold: 120.0,
                face_threshold: 0.6,
            },
            roots: vec!["/Users/someone/Pictures".into()],
            entries: paths.iter().map(|p| entry(p)).collect(),
            groups: vec![],
        }
    }

    fn plain(project: &Project, blobs: &[Vec<u8>]) -> Vec<u8> {
        write(project, blobs, Contents::default(), None, Profile::Test).unwrap()
    }

    fn sealed(project: &Project, blobs: &[Vec<u8>]) -> Vec<u8> {
        write(project, blobs, Contents::default(), Some(PW), Profile::Test).unwrap()
    }

    /// A writer that performs none of the checks `write` performs.
    ///
    /// This is the point of the whole battery: the guarantees must live in the *reader*,
    /// because the person who wrote the file you are opening did not necessarily use
    /// your writer. `edit_body` runs first and the header is then derived from the
    /// result — so lengths and digest are correct by default, exactly as they would be
    /// for an attacker who can recompute them — and `edit_head` introduces the one lie
    /// each test is actually about.
    fn craft(
        project: &Project,
        blobs: &[Vec<u8>],
        edit_body: impl FnOnce(&mut Vec<u8>),
        edit_head: impl FnOnce(&mut Header),
    ) -> Vec<u8> {
        let mut cbor = Vec::new();
        ciborium::into_writer(project, &mut cbor).unwrap();
        let manifest = miniz_oxide::deflate::compress_to_vec(&cbor, 6);

        let mut body = Vec::new();
        body.extend_from_slice(&(manifest.len() as u64).to_le_bytes());
        body.extend_from_slice(&manifest);
        for b in blobs {
            body.extend_from_slice(&(b.len() as u64).to_le_bytes());
            body.extend_from_slice(b);
        }
        edit_body(&mut body);

        let mut head = Header {
            flags: 0,
            compression: Compression::Deflate,
            kdf: None,
            frame_len: FRAME_LEN,
            manifest_len: manifest.len() as u64,
            blob_count: blobs.len() as u32,
            body_len: body.len() as u64,
            digest: crypto::digest(&body),
        };
        edit_head(&mut head);

        let mut out = header::encode(&head).unwrap();
        out.extend_from_slice(&body);
        out
    }

    /// Rewrites the header of a sealed container and leaves the ciphertext untouched —
    /// which is precisely the power an attacker has over an encrypted file: the header
    /// is in the clear, so it can be edited, and every such edit must be caught.
    fn reheader(container: &[u8], edit: impl FnOnce(&mut Header)) -> Vec<u8> {
        let (mut head, offset) = header::decode(container).unwrap();
        edit(&mut head);
        let mut out = header::encode(&head).unwrap();
        out.extend_from_slice(&container[offset..]);
        out
    }

    fn body_of(container: &[u8]) -> (usize, &[u8]) {
        let (_, offset) = header::decode(container).unwrap();
        (offset, &container[offset..])
    }

    // ------------------------------------------------------------------ round trips

    #[test]
    fn round_trip_plain() {
        let mut p = project(&["2024/beach.jpg", "2024/beach-2.jpg", "misc/cat.heic"]);
        p.groups = vec![Group { members: vec![0, 1], suggested: 0, kind: "duplicate".into() }];

        let opened = read(&plain(&p, &[]), None).unwrap();
        assert_eq!(opened.project, p, "everything comes back exactly as it went in");
        assert!(!opened.header.encrypted());
        assert!(opened.blobs.is_empty());
    }

    #[test]
    fn round_trip_encrypted() {
        let p = project(&["2024/beach.jpg", "misc/cat.heic"]);
        let container = sealed(&p, &[]);

        // A reader can tell it needs a password without having one.
        let head = peek(&container).unwrap();
        assert!(head.encrypted());
        assert_eq!(head.kdf.as_ref().unwrap().algorithm, ARGON2ID);

        assert_eq!(read(&container, Some(PW)).unwrap().project, p);
    }

    #[test]
    fn round_trip_with_thumbnails() {
        let mut p = project(&["a.jpg", "b.jpg"]);
        p.entries[0].thumbnail = Some(0);
        p.entries[1].thumbnail = Some(1);
        let blobs = vec![noise(1, 9_000), noise(2, 12_500)];

        let container =
            write(&p, &blobs, Contents { thumbnails: true, originals: false }, None, Profile::Test)
                .unwrap();
        let opened = read(&container, None).unwrap();

        assert!(opened.header.flags().contains(Flags::THUMBNAILS));
        assert!(!opened.header.flags().contains(Flags::ORIGINALS));
        assert_eq!(opened.blobs, blobs, "thumbnails survive byte for byte");
        assert_eq!(opened.project.entries[1].thumbnail, Some(1));
    }

    #[test]
    fn round_trip_with_originals() {
        let mut p = project(&["a.jpg", "b.jpg"]);
        p.entries[0].thumbnail = Some(0);
        p.entries[0].original = Some(1);
        p.entries[1].original = Some(2);
        let blobs = vec![noise(3, 4_000), noise(4, 250_000), noise(5, 310_000)];

        let container = write(
            &p,
            &blobs,
            Contents { thumbnails: true, originals: true },
            Some(PW),
            Profile::Test,
        )
        .unwrap();
        let opened = read(&container, Some(PW)).unwrap();

        assert!(opened.header.flags().contains(Flags::ORIGINALS));
        assert_eq!(opened.blobs, blobs, "originals survive byte for byte through the cipher");
    }

    #[test]
    fn round_trip_multi_frame() {
        // Four blobs of 700 KiB put the body well past three frames, so the STREAM path
        // is exercised with real intermediate frames rather than a single final one.
        let mut p = project(&["a.jpg", "b.jpg", "c.jpg", "d.jpg"]);
        for (i, e) in p.entries.iter_mut().enumerate() {
            e.original = Some(i as u32);
        }
        let blobs: Vec<Vec<u8>> = (0..4).map(|i| noise(10 + i, 700 * 1024)).collect();

        let container =
            write(&p, &blobs, Contents { thumbnails: false, originals: true }, Some(PW), Profile::Test)
                .unwrap();

        let (offset, rest) = body_of(&container);
        let head = peek(&container).unwrap();
        let frames = head.body_len.div_ceil(head.frame_len as u64);
        assert!(frames >= 3, "the fixture must actually span several frames, got {frames}");
        assert_eq!(
            container.len() as u64,
            offset as u64 + head.body_len + frames * TAG_LEN as u64,
            "the file is exactly header + body + one tag per frame"
        );
        let _ = rest;

        let opened = read(&container, Some(PW)).unwrap();
        assert_eq!(opened.blobs, blobs);
        assert_eq!(opened.project, p);
    }

    #[test]
    fn round_trip_relative_paths_relocate() {
        // The whole portability claim: a project made under one root opens under another,
        // on any operating system, because nothing absolute was ever stored per entry.
        let p = project(&["2024/summer/beach.jpg", "2024/summer/sub dir/cat.heic"]);
        let opened = read(&plain(&p, &[]), None).unwrap();

        for entry in &opened.project.entries {
            assert!(!std::path::Path::new(&entry.path).is_absolute());
            assert!(!entry.path.contains('\\'), "separators are normalised to '/' in the file");
        }

        // `Path::join` is what actually relocates. Windows accepts '/' as a separator
        // too, so the same stored string resolves correctly on all three platforms and
        // this assertion holds wherever the test runs.
        let elsewhere = std::path::Path::new("/Volumes/Backup/Photos");
        assert_eq!(
            elsewhere.join(&opened.project.entries[0].path),
            std::path::Path::new("/Volumes/Backup/Photos/2024/summer/beach.jpg")
        );

        // The roots the project was made with are a hint for the user, nothing more.
        assert_eq!(opened.project.roots, p.roots);
    }

    #[test]
    fn round_trip_portable_names() {
        // Names that are legal on one platform and awkward on another must survive the
        // container unchanged; it is the *extractor's* job to deal with the filesystem.
        let names = [
            "photos/été 2024/plage.jpg",
            "photos/日本/桜.heic",
            "photos/with space/and-dash_und.jpg",
            "photos/UPPER.JPG",
            "a.jpg",
        ];
        let opened = read(&plain(&project(&names), &[]), None).unwrap();
        let got: Vec<&str> = opened.project.entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(got, names);
    }

    #[test]
    fn a_password_on_a_plain_container_is_simply_ignored() {
        let p = project(&["a.jpg"]);
        assert_eq!(read(&plain(&p, &[]), Some(PW)).unwrap().project, p);
    }

    // ------------------------------------------------------------------ rejections

    #[test]
    fn rejects_empty_and_arbitrary_rubbish() {
        assert_eq!(read(&[], None), Err(Error::NotSkimrr));
        assert_eq!(read(b"hello", None), Err(Error::NotSkimrr));
        assert_eq!(read(&[0u8; 4096], None), Err(Error::NotSkimrr));
        assert_eq!(read(b"SKIMRR\x1A\x00", None), Err(Error::NotSkimrr), "magic alone is not a file");
        // A PNG, a ZIP: things a user might plausibly drag onto the window.
        assert_eq!(read(b"\x89PNG\r\n\x1a\n....", None), Err(Error::NotSkimrr));
        assert_eq!(read(b"PK\x03\x04....", None), Err(Error::NotSkimrr));
    }

    #[test]
    fn rejects_unknown_format_version() {
        let mut c = plain(&project(&["a.jpg"]), &[]);
        c[8] = 2;
        assert_eq!(
            read(&c, None),
            Err(Error::UnsupportedVersion { found: 2, supported: FORMAT_VERSION }),
            "a newer format must be refused outright, never parsed hopefully"
        );

        c[8] = 0;
        assert!(matches!(read(&c, None), Err(Error::UnsupportedVersion { found: 0, .. })));

        c[8] = 0xff;
        c[9] = 0xff;
        assert!(matches!(read(&c, None), Err(Error::UnsupportedVersion { found: 65535, .. })));
    }

    #[test]
    fn rejects_a_flipped_bit_anywhere_in_the_header() {
        let container = sealed(&project(&["a.jpg"]), &[]);
        let (offset, _) = body_of(&container);

        for i in 0..offset {
            for bit in [0u8, 3, 7] {
                let mut c = container.clone();
                c[i] ^= 1 << bit;
                if c == container {
                    continue;
                }
                assert!(
                    read(&c, Some(PW)).is_err(),
                    "byte {i} bit {bit} of the header was flipped and the file still opened"
                );
            }
        }
    }

    /// The associated-data property, isolated.
    ///
    /// These three edits leave every length in the file consistent and leave the header
    /// perfectly parseable, so nothing but the AEAD can catch them. Two of the fields are
    /// not even *used* when the container is encrypted — which is the point: authenticated
    /// means all of it, not just the parts the reader happens to consult.
    #[test]
    fn every_header_field_is_authenticated_even_the_unused_ones() {
        let container = sealed(&project(&["a.jpg", "b.jpg"]), &[]);
        assert!(read(&container, Some(PW)).is_ok());

        type Edit = Box<dyn Fn(&mut Header)>;
        let edits: Vec<(&str, Edit)> = vec![
            // Ignored entirely on an encrypted container: the AEAD tag is the real check.
            ("digest", Box::new(|h: &mut Header| h.digest[0] ^= 0xff)),
            // Parses fine, changes nothing about the layout, would silently mangle the
            // manifest if it were believed.
            ("compression", Box::new(|h: &mut Header| h.compression = Compression::None)),
            // A cosmetic flag the reader shows in the UI.
            ("flags", Box::new(|h: &mut Header| h.flags |= Flags::THUMBNAILS.bits())),
        ];

        for (field, edit) in edits {
            let c = reheader(&container, |h| edit(h));
            assert_ne!(c, container, "the {field} edit must actually change the bytes");
            assert!(peek(&c).is_ok(), "the {field} edit is supposed to stay parseable");
            assert_eq!(
                read(&c, Some(PW)),
                Err(Error::WrongPasswordOrTampered),
                "editing {field} in the clear-text header must break authentication"
            );
        }
    }

    #[test]
    fn rejects_inconsistent_flags() {
        let p = project(&["a.jpg"]);

        // Claims to be encrypted, carries no key derivation.
        let c = craft(&p, &[], |_| {}, |h| h.flags |= Flags::ENCRYPTED.bits());
        assert_eq!(read(&c, Some(PW)), Err(Error::MalformedHeader("encrypted with no key derivation")));

        // Carries a key derivation but claims to be plain — the reader would otherwise
        // hand back "decrypted" content it never decrypted.
        let c = craft(&p, &[], |_| {}, |h| h.kdf = Some(Profile::Test.new_kdf()));
        assert_eq!(read(&c, None), Err(Error::MalformedHeader("key derivation on a plain container")));

        // A flag this build does not know. Refusing rather than truncating means a file
        // using a future feature is never half-understood.
        let c = craft(&p, &[], |_| {}, |h| h.flags |= 1 << 9);
        assert_eq!(read(&c, None), Err(Error::MalformedHeader("unknown flag")));
    }

    #[test]
    fn rejects_implausible_key_derivation_parameters() {
        let p = project(&["a.jpg"]);
        let bad = [
            ("algorithm", Kdf { algorithm: 9, m_kib: 8192, t: 1, p: 1, salt: [0; 16], nonce: [0; 19] }),
            // Low enough to be brute-forced.
            ("too cheap", Kdf { algorithm: ARGON2ID, m_kib: 64, t: 1, p: 1, salt: [0; 16], nonce: [0; 19] }),
            // High enough to be a denial of service against the person opening the file.
            ("too dear", Kdf { algorithm: ARGON2ID, m_kib: 4 * 1024 * 1024, t: 1, p: 1, salt: [0; 16], nonce: [0; 19] }),
            ("zero passes", Kdf { algorithm: ARGON2ID, m_kib: 8192, t: 0, p: 1, salt: [0; 16], nonce: [0; 19] }),
            ("absurd passes", Kdf { algorithm: ARGON2ID, m_kib: 8192, t: 99, p: 1, salt: [0; 16], nonce: [0; 19] }),
            ("zero lanes", Kdf { algorithm: ARGON2ID, m_kib: 8192, t: 1, p: 0, salt: [0; 16], nonce: [0; 19] }),
        ];
        for (why, kdf) in bad {
            let c = craft(&p, &[], |_| {}, |h| {
                h.flags |= Flags::ENCRYPTED.bits();
                h.kdf = Some(kdf.clone());
            });
            assert!(
                matches!(read(&c, Some(PW)), Err(Error::MalformedHeader(_))),
                "a container with {why} must be refused before any work is done"
            );
        }
    }

    #[test]
    fn rejects_truncation_at_every_offset() {
        for container in [plain(&project(&["a.jpg"]), &[noise(1, 5000)]),
                          sealed(&project(&["a.jpg"]), &[noise(1, 5000)])] {
            let encrypted = peek(&container).map(|h| h.encrypted()).unwrap_or(false);
            let password = encrypted.then_some(PW);

            // Every prefix, including the empty one. None may open, and none may panic.
            for cut in 0..container.len() {
                assert!(
                    read(&container[..cut], password).is_err(),
                    "a container truncated to {cut} of {} bytes opened",
                    container.len()
                );
            }
            assert!(read(&container, password).is_ok(), "the untruncated file still opens");
        }
    }

    #[test]
    fn rejects_a_missing_frame() {
        let mut p = project(&["a.jpg", "b.jpg", "c.jpg", "d.jpg"]);
        for (i, e) in p.entries.iter_mut().enumerate() {
            e.original = Some(i as u32);
        }
        let blobs: Vec<Vec<u8>> = (0..4).map(|i| noise(20 + i, 700 * 1024)).collect();
        let container =
            write(&p, &blobs, Contents { thumbnails: false, originals: true }, Some(PW), Profile::Test)
                .unwrap();
        let head = peek(&container).unwrap();
        let frame = head.frame_len as usize + TAG_LEN;

        // Simply dropping the last frame: caught by the length the header declares.
        let short = &container[..container.len() - frame];
        assert!(matches!(read(short, Some(PW)), Err(Error::MalformedBody(_))));

        // The interesting version — the attacker also rewrites the header so the
        // arithmetic works out. The header is authenticated, so it cannot be done.
        let dropped = {
            let (offset, _) = body_of(&container);
            let sealed_len = container.len() - offset;
            let mut c = reheader(&container, |h| h.body_len -= h.frame_len as u64);
            // Re-encoding may not produce a header of the same length, so the cut is
            // measured against the rewritten file rather than the original.
            let new_offset = header::decode(&c).unwrap().1;
            c.truncate(new_offset + sealed_len - frame);
            c
        };
        assert_eq!(
            read(&dropped, Some(PW)),
            Err(Error::WrongPasswordOrTampered),
            "shortening the stream is not something a header edit can legitimise"
        );
    }

    #[test]
    fn rejects_an_extra_frame_after_the_end() {
        let container = sealed(&project(&["a.jpg"]), &[noise(1, 5000)]);

        for extra in [1usize, 16, 64, 1024] {
            let mut c = container.clone();
            c.extend_from_slice(&noise(7, extra));
            assert!(
                matches!(read(&c, Some(PW)), Err(Error::MalformedBody(_))),
                "{extra} bytes appended after the final frame were accepted"
            );
        }

        // A whole well-formed-looking frame appended, rather than rubbish.
        let mut c = container.clone();
        let (_, rest) = body_of(&container);
        c.extend_from_slice(rest);
        assert!(matches!(read(&c, Some(PW)), Err(Error::MalformedBody(_))));
    }

    #[test]
    fn rejects_reordered_and_duplicated_frames() {
        let mut p = project(&["a.jpg", "b.jpg", "c.jpg", "d.jpg"]);
        for (i, e) in p.entries.iter_mut().enumerate() {
            e.original = Some(i as u32);
        }
        let blobs: Vec<Vec<u8>> = (0..4).map(|i| noise(30 + i, 700 * 1024)).collect();
        let container =
            write(&p, &blobs, Contents { thumbnails: false, originals: true }, Some(PW), Profile::Test)
                .unwrap();

        let (offset, _) = body_of(&container);
        let frame = peek(&container).unwrap().frame_len as usize + TAG_LEN;

        // Swapping two full frames keeps the file exactly the right length, so only the
        // authenticated chunk counter can catch it.
        let mut swapped = container.clone();
        for i in 0..frame {
            swapped.swap(offset + i, offset + frame + i);
        }
        assert_eq!(
            read(&swapped, Some(PW)),
            Err(Error::WrongPasswordOrTampered),
            "reordering frames must fail"
        );

        // Replaying frame 0 in slot 1: a falsified chunk index by another name.
        let mut replayed = container.clone();
        let first: Vec<u8> = container[offset..offset + frame].to_vec();
        replayed[offset + frame..offset + 2 * frame].copy_from_slice(&first);
        assert_eq!(
            read(&replayed, Some(PW)),
            Err(Error::WrongPasswordOrTampered),
            "duplicating a frame must fail"
        );
    }

    #[test]
    fn rejects_a_falsified_frame_length() {
        let container = sealed(&project(&["a.jpg"]), &[noise(1, 900_000)]);
        assert!(read(&container, Some(PW)).is_ok());

        for len in [1u32, 1024, 512 * 1024, 2 * 1024 * 1024, MAX_FRAME_LEN] {
            let c = reheader(&container, |h| h.frame_len = len);
            assert!(
                read(&c, Some(PW)).is_err(),
                "a frame length of {len} was accepted; frame boundaries must come from \
                 the authenticated header and nowhere else"
            );
        }

        let c = reheader(&container, |h| h.frame_len = 0);
        assert_eq!(read(&c, Some(PW)), Err(Error::MalformedHeader("implausible frame length")));
        let c = reheader(&container, |h| h.frame_len = MAX_FRAME_LEN + 1);
        assert_eq!(read(&c, Some(PW)), Err(Error::MalformedHeader("implausible frame length")));
    }

    /// A header may declare a two-terabyte body in one-byte frames. On a 64-bit machine
    /// that is merely absurd; in WebAssembly, where `usize` is 32 bits, computing the
    /// frame count before checking the length would truncate it. The arithmetic stays in
    /// `u64` until the file has been shown to be the length it claims.
    #[test]
    fn rejects_a_frame_count_that_would_not_fit_in_a_machine_word() {
        let container = sealed(&project(&["a.jpg"]), &[noise(1, 5000)]);

        for (frame_len, body_len) in [
            (1u32, MAX_BODY_LEN),
            (1, u32::MAX as u64),
            (1, (u32::MAX as u64) * 4),
            (2, MAX_BODY_LEN),
            (16, MAX_BODY_LEN),
        ] {
            let c = reheader(&container, |h| {
                h.frame_len = frame_len;
                h.body_len = body_len;
            });
            // Rejected on the arithmetic or on the length, never by wrapping into
            // agreement — and never by panicking, which a debug build would do.
            assert!(
                matches!(read(&c, Some(PW)), Err(Error::MalformedBody(_)) | Err(Error::MalformedHeader(_)) | Err(Error::TooLarge { .. })),
                "frame_len {frame_len} with body_len {body_len} was not refused"
            );
        }
    }

    #[test]
    fn rejects_a_blob_count_that_does_not_match_the_body() {
        let mut p = project(&["a.jpg", "b.jpg"]);
        p.entries[0].thumbnail = Some(0);
        p.entries[1].thumbnail = Some(1);
        let blobs = vec![noise(1, 1000), noise(2, 1000)];

        // One blob promised, none delivered: the body runs out where a length was due.
        let c = craft(&p, &blobs, |body| body.truncate(body.len() - 1000 - 8), |_| {});
        assert!(matches!(read(&c, None), Err(Error::MalformedManifest) | Err(Error::MalformedBody(_))));

        // An extra blob nobody claimed: bytes left over after the last one.
        let c = craft(&p, &blobs, |body| {
            body.extend_from_slice(&500u64.to_le_bytes());
            body.extend_from_slice(&noise(3, 500));
        }, |_| {});
        assert_eq!(read(&c, None), Err(Error::MalformedBody("trailing data after the last blob")));

        // The count itself lowered, so a blob is silently dropped and its bytes become
        // trailing data rather than being handed back under the wrong index.
        let c = craft(&p, &blobs, |_| {}, |h| h.blob_count = 1);
        assert!(read(&c, None).is_err());
    }

    #[test]
    fn rejects_a_manifest_that_claims_a_blob_twice() {
        let mut p = project(&["a.jpg", "b.jpg"]);
        p.entries[0].thumbnail = Some(0);
        p.entries[1].thumbnail = Some(0); // the same payload, claimed twice

        let blobs = vec![noise(1, 1000)];
        assert_eq!(
            write(&p, &blobs, Contents { thumbnails: true, originals: false }, None, Profile::Test),
            Err(Error::MalformedManifest),
            "the writer must not produce a manifest whose accounting is ambiguous"
        );

        let c = craft(&p, &blobs, |_| {}, |_| {});
        assert_eq!(read(&c, None), Err(Error::MalformedManifest), "and the reader must refuse one");
    }

    #[test]
    fn rejects_a_manifest_pointing_past_the_blobs_it_has() {
        let mut p = project(&["a.jpg"]);
        p.entries[0].original = Some(7);
        assert_eq!(write(&p, &[noise(1, 10)], Contents::default(), None, Profile::Test), Err(Error::MalformedManifest));
        assert_eq!(read(&craft(&p, &[noise(1, 10)], |_| {}, |_| {}), None), Err(Error::MalformedManifest));

        // Group indices are checked the same way.
        let mut p = project(&["a.jpg"]);
        p.groups = vec![Group { members: vec![0, 4], suggested: 0, kind: "duplicate".into() }];
        assert_eq!(read(&craft(&p, &[], |_| {}, |_| {}), None), Err(Error::MalformedManifest));

        let mut p = project(&["a.jpg"]);
        p.groups = vec![Group { members: vec![0], suggested: 3, kind: "duplicate".into() }];
        assert_eq!(read(&craft(&p, &[], |_| {}, |_| {}), None), Err(Error::MalformedManifest));

        // An entry naming a root that does not exist.
        let mut p = project(&["a.jpg"]);
        p.entries[0].root = 5;
        assert_eq!(read(&craft(&p, &[], |_| {}, |_| {}), None), Err(Error::MalformedManifest));
    }

    #[test]
    fn rejects_unsafe_paths_on_the_way_out() {
        let hostile = [
            "../escape.jpg",
            "a/../../escape.jpg",
            "a/b/../../../etc/passwd",
            "/etc/passwd",
            "/",
            "//server/share/x.jpg",
            "C:/Windows/System32/x.jpg",
            "c:x.jpg",
            "..",
            ".",
            "./a.jpg",
            "a//b.jpg",
            "a/",
            "",
            "a\\..\\..\\b.jpg",
            "a\\b.jpg",
            "nul",
            "a/CON/b.jpg",
            "a/lpt1.txt",
            "com9.jpg",
            "trailing./x.jpg",
            "trailing /x.jpg",
            "a/b.jpg.",
            "with\0nul.jpg",
        ];
        for path in hostile {
            let p = project(&[path]);
            assert_eq!(
                write(&p, &[], Contents::default(), None, Profile::Test),
                Err(Error::UnsafePath),
                "the writer accepted the path {path:?}"
            );
        }

        let long = format!("{}.jpg", "a".repeat(2000));
        assert_eq!(
            write(&project(&[&long]), &[], Contents::default(), None, Profile::Test),
            Err(Error::UnsafePath)
        );
    }

    #[test]
    fn rejects_unsafe_paths_on_the_way_in() {
        // The writer's checks are a convenience; these are the ones that matter, because
        // this container was not written by us.
        for path in ["../../../../etc/passwd", "/etc/passwd", "C:/Windows/x.dll", "a/../../b.jpg", "a\\..\\b.jpg"] {
            let c = craft(&project(&[path]), &[], |_| {}, |_| {});
            assert_eq!(read(&c, None), Err(Error::UnsafePath), "the reader accepted {path:?}");
        }

        // And the same, sealed under a valid key: authentic hostile data is still
        // hostile data, and a passing tag is not a reason to skip validation.
        let p = project(&["ok.jpg"]);
        let mut hostile = p.clone();
        hostile.entries[0].path = "../../secrets.jpg".into();
        let mut cbor = Vec::new();
        ciborium::into_writer(&hostile, &mut cbor).unwrap();
        let manifest = miniz_oxide::deflate::compress_to_vec(&cbor, 6);
        let mut body = Vec::new();
        body.extend_from_slice(&(manifest.len() as u64).to_le_bytes());
        body.extend_from_slice(&manifest);
        let kdf = Profile::Test.new_kdf();
        let head = Header {
            flags: Flags::ENCRYPTED.bits(),
            compression: Compression::Deflate,
            kdf: Some(kdf.clone()),
            frame_len: FRAME_LEN,
            manifest_len: manifest.len() as u64,
            blob_count: 0,
            body_len: body.len() as u64,
            digest: crypto::digest(&body),
        };
        let prefix = header::encode(&head).unwrap();
        let key = crypto::derive_key(PW, &kdf).unwrap();
        let sealer = crypto::Sealer::new(&key, &kdf, prefix.clone());
        let mut c = prefix;
        c.extend_from_slice(&sealer.last(&body).unwrap());

        assert_eq!(
            read(&c, Some(PW)),
            Err(Error::UnsafePath),
            "a correctly sealed container with a traversal path must still be refused"
        );
    }

    #[test]
    fn rejects_absurd_declared_sizes() {
        let p = project(&["a.jpg"]);

        let c = craft(&p, &[], |_| {}, |h| h.manifest_len = u64::MAX);
        assert_eq!(read(&c, None), Err(Error::TooLarge { limit: MAX_MANIFEST_LEN }));

        let c = craft(&p, &[], |_| {}, |h| h.manifest_len = 0);
        assert_eq!(read(&c, None), Err(Error::TooLarge { limit: MAX_MANIFEST_LEN }));

        let c = craft(&p, &[], |_| {}, |h| h.body_len = u64::MAX);
        assert_eq!(read(&c, None), Err(Error::TooLarge { limit: MAX_BODY_LEN }));

        let c = craft(&p, &[], |_| {}, |h| h.blob_count = u32::MAX);
        assert_eq!(read(&c, None), Err(Error::TooLarge { limit: MAX_BLOBS as u64 }));

        // Within the ceiling, but two million blobs promised by a two-kilobyte file.
        // This must fail on the missing bytes, not on an allocation the size of the lie.
        let c = craft(&p, &[], |_| {}, |h| h.blob_count = MAX_BLOBS);
        assert!(matches!(read(&c, None), Err(Error::MalformedBody(_))));

        // A manifest longer than the body that is supposed to contain it.
        let c = craft(&p, &[], |_| {}, |h| h.manifest_len = h.body_len + 1);
        assert_eq!(read(&c, None), Err(Error::MalformedHeader("manifest longer than the body holding it")));

        // A blob length prefix inside the body promising more than the file holds. The
        // bounds check has to come before the allocation, which is what this pins down.
        let mut p2 = project(&["a.jpg"]);
        p2.entries[0].thumbnail = Some(0);
        let c = craft(&p2, &[noise(1, 100)], |body| {
            let at = body.len() - 100 - 8;
            body[at..at + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        }, |_| {});
        assert!(matches!(read(&c, None), Err(Error::MalformedBody(_))));

        // The same, just under usize::MAX, where a naive `+ len` would wrap.
        let c = craft(&p2, &[noise(1, 100)], |body| {
            let at = body.len() - 100 - 8;
            body[at..at + 8].copy_from_slice(&(usize::MAX as u64 - 4).to_le_bytes());
        }, |_| {});
        assert!(matches!(read(&c, None), Err(Error::MalformedBody(_))));
    }

    #[test]
    fn rejects_a_manifest_length_that_disagrees_with_the_header() {
        let p = project(&["a.jpg", "b.jpg"]);
        // The body says one thing in its own length prefix, the header another. Believing
        // either without checking the other is how parsers get desynchronised.
        let c = craft(&p, &[], |body| body[0] = body[0].wrapping_add(1), |_| {});
        assert!(read(&c, None).is_err());
    }

    #[test]
    fn rejects_trailing_data_after_the_container() {
        for (container, pw) in
            [(plain(&project(&["a.jpg"]), &[]), None), (sealed(&project(&["a.jpg"]), &[]), Some(PW))]
        {
            for junk in [&b"x"[..], &b"SKIMRR\x1A\x00"[..], &[0u8; 4096][..]] {
                let mut c = container.clone();
                c.extend_from_slice(junk);
                assert!(
                    matches!(read(&c, pw), Err(Error::MalformedBody(_))),
                    "{} bytes appended to the end of the container were ignored",
                    junk.len()
                );
            }
        }
    }

    #[test]
    fn rejects_a_wrong_or_missing_password() {
        let container = sealed(&project(&["a.jpg"]), &[]);

        assert_eq!(read(&container, Some("nope")), Err(Error::WrongPasswordOrTampered));
        assert_eq!(read(&container, Some("")), Err(Error::WrongPasswordOrTampered));
        // Off by one character, and off by a trailing space: no partial credit.
        assert_eq!(read(&container, Some("correct horse battery stapl")), Err(Error::WrongPasswordOrTampered));
        assert_eq!(read(&container, Some("correct horse battery staple ")), Err(Error::WrongPasswordOrTampered));
        assert_eq!(read(&container, None), Err(Error::WrongPasswordOrTampered));
        assert!(read(&container, Some(PW)).is_ok());
    }

    #[test]
    fn a_damaged_plain_container_is_refused_rather_than_repaired() {
        let container = plain(&project(&["a.jpg"]), &[noise(1, 4000)]);
        let (offset, _) = body_of(&container);

        for at in [offset, offset + 100, container.len() - 1] {
            let mut c = container.clone();
            c[at] ^= 0x40;
            assert!(
                read(&c, None).is_err(),
                "a bit flipped at {at} was not noticed; a digest that is never checked is \
                 worse than none at all"
            );
        }
    }

    /// The limit of an unencrypted container, stated as a test so it cannot be quietly
    /// forgotten.
    ///
    /// Without a key there is no authenticity to be had — only integrity. Anyone who can
    /// rewrite the body can recompute the digest, and this passes. That is not a defect
    /// to be fixed with a cleverer checksum; it is what "no key" means, and the answer
    /// for a file that must not be forged is to encrypt it.
    #[test]
    fn an_unencrypted_container_is_protected_against_damage_but_not_against_forgery() {
        let honest = project(&["holiday/a.jpg"]);
        let container = plain(&honest, &[]);
        assert_eq!(read(&container, None).unwrap().project, honest);

        let mut forged = honest.clone();
        forged.name = "not what the sender wrote".into();
        forged.entries[0].kept = false;
        let c = craft(&forged, &[], |_| {}, |_| {});

        assert_eq!(
            read(&c, None).unwrap().project,
            forged,
            "an unencrypted container carries no proof of who wrote it"
        );
        // What it does still catch, and must: damage.
        let mut damaged = c.clone();
        let at = body_of(&c).0 + 12;
        damaged[at] ^= 0x20;
        assert_eq!(read(&damaged, None), Err(Error::Corrupted));

        // And the same forgery attempted against a sealed container fails, which is the
        // reason encryption is offered in the first place.
        let sealed_honest = sealed(&honest, &[]);
        let (offset, _) = body_of(&sealed_honest);
        let mut spliced = sealed_honest.clone();
        let (_, forged_rest) = body_of(&c);
        spliced.truncate(offset);
        spliced.extend_from_slice(forged_rest);
        assert!(read(&spliced, Some(PW)).is_err());
    }

    #[test]
    fn the_manifest_is_not_a_decompression_bomb() {
        // A few kilobytes that become megabytes. `read` inflates through
        // `decompress_to_vec_with_limit`, so the ceiling is the reader's, not the file's.
        let bomb = miniz_oxide::deflate::compress_to_vec(&vec![0u8; 8 * 1024 * 1024], 9);
        assert!(bomb.len() < 64 * 1024, "the fixture must actually be a bomb: {} bytes", bomb.len());

        assert!(
            miniz_oxide::inflate::decompress_to_vec_with_limit(&bomb, 1024 * 1024).is_err(),
            "the limited inflate must refuse to exceed the ceiling it is given"
        );
        assert_eq!(
            miniz_oxide::inflate::decompress_to_vec_with_limit(&bomb, MAX_MANIFEST_PLAIN).unwrap().len(),
            8 * 1024 * 1024
        );

        // At the container level: garbage in the manifest slot must not be mistaken for
        // a project, whatever it inflates to.
        let p = project(&["a.jpg"]);
        let c = craft(&p, &[], |body| {
            body.clear();
            body.extend_from_slice(&(bomb.len() as u64).to_le_bytes());
            body.extend_from_slice(&bomb);
        }, |h| h.manifest_len = bomb.len() as u64);
        assert_eq!(read(&c, None), Err(Error::MalformedManifest));
    }

    #[test]
    fn never_panics_on_hostile_bytes() {
        let mut p = project(&["a.jpg", "b/c.jpg"]);
        p.entries[0].thumbnail = Some(0);
        p.groups = vec![Group { members: vec![0, 1], suggested: 1, kind: "duplicate".into() }];
        let valid = plain(&p, &[noise(1, 3000)]);

        let mut s = 0x5eed_u64;
        let mut next = move || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };

        // Mutations of a real file: the shape stays plausible, so the parser gets much
        // further in before it has to refuse.
        for _ in 0..4000 {
            let mut c = valid.clone();
            for _ in 0..=(next() % 3) {
                let i = (next() as usize) % c.len();
                c[i] ^= 1 << (next() % 8);
            }
            let _ = read(&c, None);
            let _ = peek(&c);
        }

        // And bytes with no shape at all, with and without a convincing magic number.
        for _ in 0..4000 {
            let len = (next() as usize) % 256;
            let bytes: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let _ = read(&bytes, None);
            let mut with_magic = MAGIC.to_vec();
            with_magic.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
            with_magic.extend_from_slice(&bytes);
            let _ = read(&with_magic, None);
            let _ = read(&with_magic, Some(PW));
            let _ = peek(&with_magic);
        }
    }

    #[test]
    fn no_error_can_carry_the_password() {
        // The constraint is that a password never reaches disk, a log, or a message. The
        // last of those is the easy one to break by accident, so it is pinned here.
        let secret = "hunter2-swordfish-correct-horse";
        let container = sealed(&project(&["a.jpg"]), &[]);

        let mut messages = Vec::new();
        messages.push(format!("{:?}", read(&container, Some(secret)).err().unwrap()));
        messages.push(format!("{}", read(&container, Some(secret)).err().unwrap()));
        for c in [&[][..], b"garbage", &container[..30]] {
            if let Err(e) = read(c, Some(secret)) {
                messages.push(format!("{e:?} {e}"));
            }
        }
        for m in messages {
            assert!(!m.contains(secret), "an error message leaked the password: {m}");
            assert!(!m.contains("hunter2"), "an error message leaked part of the password: {m}");
        }
    }

    #[test]
    fn the_writer_refuses_what_the_reader_would_refuse() {
        // Anything the reader rejects, the writer must never produce — otherwise Skimrr
        // writes files it cannot open, which is the one bug a format cannot afford.
        let cases: Vec<Project> = vec![
            {
                let mut p = project(&["../x.jpg"]);
                p.roots = vec!["/r".into()];
                p
            },
            {
                let mut p = project(&["a.jpg"]);
                p.roots.clear();
                p
            },
            {
                let mut p = project(&["a.jpg"]);
                p.groups = vec![Group { members: vec![], suggested: 0, kind: "duplicate".into() }];
                p
            },
        ];
        for p in cases {
            assert!(write(&p, &[], Contents::default(), None, Profile::Test).is_err());
        }
    }
}

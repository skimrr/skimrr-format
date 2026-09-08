//! Writes a large container, to measure what opening one costs.
//!
//! Usage: `cargo run --release --example big -- out.skimrr <megabytes> [password]`
//!
//! Deliberately a separate process from the reader: measuring peak memory means
//! measuring the read alone, and a process that has just built the thing in memory
//! carries a high-water mark that has nothing to do with opening it.

use skimrr_format as fmt;

fn main() {
    let mut args = std::env::args().skip(1);
    let out = args.next().expect("usage: big <out.skimrr> <megabytes> [password]");
    let megabytes: usize = args.next().expect("megabytes").parse().expect("a number");
    let password = args.next();

    // Photograph-sized blobs of incompressible bytes, which is what real originals are.
    const BLOB: usize = 4 * 1024 * 1024;
    let count = (megabytes * 1024 * 1024) / BLOB;

    let blobs: Vec<Vec<u8>> = (0..count)
        .map(|i| {
            let mut s = (i as u64) | 1;
            (0..BLOB)
                .map(|_| {
                    s ^= s << 13;
                    s ^= s >> 7;
                    s ^= s << 17;
                    (s >> 24) as u8
                })
                .collect()
        })
        .collect();

    let entries = (0..count)
        .map(|i| fmt::Entry {
            root: 0,
            path: format!("{}/{:05}.jpg", i / 500, i),
            size: BLOB as u64,
            sha: Some(format!("{i:064x}")),
            phash: Some(format!("{i:032x}")),
            taken: 1_700_000_000 + i as i64,
            blur: Some(100.0),
            bad_shot: None,
            extra: None,
            kept: true,
            thumbnail: None,
            original: Some(i as u32),
        })
        .collect();

    let project = fmt::Project {
        name: format!("{megabytes} MB of originals"),
        created: 1_700_000_000,
        settings: fmt::Settings {
            similarity_threshold: 28,
            blur_threshold: 120.0,
            face_threshold: 0.6,
        },
        roots: vec!["/Users/someone/Pictures".into()],
        entries,
        groups: vec![],
    };

    let bytes = fmt::write(
        &project,
        &blobs,
        fmt::Contents { thumbnails: false, originals: true },
        password.as_deref(),
        fmt::Profile::Strong,
    )
    .expect("writable");
    std::fs::write(&out, &bytes).expect("could not write");
    println!("wrote {out} — {} photographs, {} MB", count, bytes.len() / 1024 / 1024);
}

//! Writes a sample `.skimrr`, so the browser proof has something real to open.
//!
//! Usage: `cargo run --example make_sample -- out.skimrr [password]`

use skimrr_format as fmt;

fn main() {
    let mut args = std::env::args().skip(1);
    let out = args.next().unwrap_or_else(|| "sample.skimrr".into());
    let password = args.next();

    let paths = [
        "2024/corse/plage.jpg",
        "2024/corse/plage-2.jpg",
        "2024/corse/plage-3.jpg",
        "2024/été/marché.heic",
        "2023/hiver/neige.jpg",
    ];

    // A thumbnail for each, so the demo has a blob to hand back as well as a manifest.
    let blobs: Vec<Vec<u8>> = (0..paths.len())
        .map(|i| (0..4096).map(|b| ((b * 31 + i * 7) % 251) as u8).collect())
        .collect();

    let entries = paths
        .iter()
        .enumerate()
        .map(|(i, path)| fmt::Entry {
            root: 0,
            path: (*path).into(),
            size: 4_800_000 + i as u64 * 12_345,
            sha: Some(format!("{:064x}", i + 1)),
            phash: Some(format!("{:032x}", 0x0f1e_2d3c_4b5a_6978u128 + i as u128)),
            taken: 1_700_000_000 + i as i64 * 86_400,
            blur: Some(90.0 + i as f64 * 15.0),
            bad_shot: None,
            extra: None,
            kept: i != 1,
            thumbnail: Some(i as u32),
            original: None,
        })
        .collect();

    let project = fmt::Project {
        name: "Été 2024 — Corse".into(),
        created: 1_700_000_000,
        settings: fmt::Settings {
            similarity_threshold: 28,
            blur_threshold: 120.0,
            face_threshold: 0.6,
        },
        roots: vec!["/Users/someone/Pictures".into()],
        entries,
        groups: vec![fmt::Group {
            members: vec![0, 1, 2],
            suggested: 0,
            kind: "similar".into(),
        }],
    };

    let bytes = fmt::write(
        &project,
        &blobs,
        fmt::Contents { thumbnails: true, originals: false },
        password.as_deref(),
        fmt::Profile::Strong,
    )
    .expect("the sample must be writable");

    std::fs::write(&out, &bytes).expect("could not write the sample");
    println!(
        "wrote {out} — {} bytes, {}",
        bytes.len(),
        if password.is_some() { "encrypted" } else { "plain" }
    );
}

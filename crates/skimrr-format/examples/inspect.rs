//! Reads a `.skimrr` and says what is in it.
//!
//! Independent of the application on purpose: when the question is "did Skimrr write
//! what it said it wrote", the answer has to come from something other than Skimrr.
//!
//! Usage: `cargo run --example inspect -- file.skimrr [password]`

use skimrr_format as fmt;

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("usage: inspect <file.skimrr> [password]");
    let password = args.next();

    let bytes = std::fs::read(&path).expect("could not read the file");
    println!("file           {path}");
    println!("size           {} bytes", bytes.len());

    let header = match fmt::peek(&bytes) {
        Ok(h) => h,
        Err(e) => {
            println!("HEADER         refused: {e}");
            std::process::exit(1);
        }
    };
    println!("encrypted      {}", header.encrypted());
    println!(
        "carries        {}",
        match (
            header.flags().contains(fmt::Flags::ORIGINALS),
            header.flags().contains(fmt::Flags::THUMBNAILS),
        ) {
            (true, _) => "the photographs",
            (false, true) => "previews",
            _ => "findings only",
        }
    );
    if let Some(kdf) = &header.kdf {
        println!(
            "kdf            Argon2id, {} MiB, t={}, p={}",
            kdf.m_kib / 1024,
            kdf.t,
            kdf.p
        );
    }
    println!("body           {} bytes in {} blobs", header.body_len, header.blob_count);
    println!(
        "frames         {}",
        header.body_len.div_ceil(header.frame_len as u64)
    );

    let opened = match fmt::read(&bytes, password.as_deref()) {
        Ok(o) => o,
        Err(e) => {
            println!("OPEN           refused: {e}");
            std::process::exit(1);
        }
    };
    let project = opened.project;
    println!("name           {}", project.name);
    println!("photographs    {}", project.entries.len());
    println!("groups         {}", project.groups.len());
    println!("roots          {:?}", project.roots);
    println!("threshold      {}", project.settings.similarity_threshold);

    let with_thumb = project.entries.iter().filter(|e| e.thumbnail.is_some()).count();
    let with_orig = project.entries.iter().filter(|e| e.original.is_some()).count();
    let kept = project.entries.iter().filter(|e| e.kept).count();
    println!("thumbnails     {with_thumb}");
    println!("originals      {with_orig}");
    println!("marked kept    {kept}");
    println!();

    if project.entries.len() > 60 {
        println!("  (entries not listed: {} of them)", project.entries.len());
        return;
    }
    for (i, entry) in project.entries.iter().enumerate() {
        println!(
            "  [{i:>3}] {:<44} {:>9} B  sha {}  {}",
            entry.path,
            entry.size,
            entry.sha.as_deref().map(|s| &s[..12]).unwrap_or("—"),
            if entry.kept { "keep" } else { "" }
        );
    }
    if !project.groups.is_empty() {
        println!();
        for group in &project.groups {
            println!(
                "  group {:<10} members {:?}  keeper {}",
                group.kind, group.members, group.members[group.suggested as usize]
            );
        }
    }
}

//! A browser can open a `.skimrr`.
//!
//! That is the entire claim, and this crate exists to prove it rather than to be a web
//! application. It links the same `skimrr-format` the desktop application links — the
//! same framing, the same Argon2id, the same XChaCha20-Poly1305 — because a second
//! implementation for the web is exactly the thing that eventually disagrees with the
//! first about what a valid file is.
//!
//! Nothing here uploads anything. There is no network code in this crate and none in
//! what it depends on: the bytes come from a file the user picked, through
//! `WebAssembly.Memory`, and the answer goes back the same way.
//!
//! # The interface
//!
//! Four exports, all plain C ABI:
//!
//! - `sk_alloc(len) -> ptr` — a buffer for JavaScript to write into
//! - `sk_dealloc(ptr, len)` — give it back
//! - `sk_peek(ptr, len) -> ptr` — what the file says about itself, no key needed
//! - `sk_open(ptr, len, pw_ptr, pw_len) -> ptr` — open it
//!
//! Both readers return a pointer to `[u32 little-endian length][UTF-8 JSON]`, freed with
//! `sk_free`. A null pointer is never returned; failures come back as JSON with
//! `"ok": false`, so the caller has one path to handle rather than two.

use serde_json::json;
use skimrr_format as fmt;
use std::cell::RefCell;

thread_local! {
    /// The one container currently open.
    ///
    /// A viewer shows the project it has just opened and nothing else, so one slot is
    /// enough — and keeping it is what makes a grid of thumbnails possible at all.
    /// Without it every image would re-derive the key: Argon2id at 128 MiB is a quarter
    /// of a second by design, so thirty thumbnails would have cost eight seconds of
    /// deliberate work to decrypt bytes already decrypted once.
    ///
    /// The password is *not* kept here. It is used, wiped by the caller, and never
    /// needed again; what stays is the plaintext the user asked to see, for as long as
    /// they are looking at it. `sk_forget` drops it.
    static OPEN: RefCell<Option<fmt::Opened>> = const { RefCell::new(None) };
}

/// A buffer for JavaScript to write a file into.
///
/// # Safety
/// The caller must eventually pass the pointer back to `sk_dealloc` with the same length.
#[no_mangle]
pub extern "C" fn sk_alloc(len: usize) -> *mut u8 {
    let buffer = vec![0u8; len].into_boxed_slice();
    Box::into_raw(buffer) as *mut u8
}

/// # Safety
/// `ptr` must have come from `sk_alloc` with this exact `len`, and not been freed.
#[no_mangle]
pub unsafe extern "C" fn sk_dealloc(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        drop(Box::from_raw(core::ptr::slice_from_raw_parts_mut(ptr, len)));
    }
}

/// # Safety
/// `ptr` must have come from `sk_peek` or `sk_open`, and not been freed.
#[no_mangle]
pub unsafe extern "C" fn sk_free(ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }
    let header = core::slice::from_raw_parts(ptr, 4);
    let len = u32::from_le_bytes(header.try_into().unwrap()) as usize;
    drop(Box::from_raw(core::ptr::slice_from_raw_parts_mut(ptr, 4 + len)));
}

fn reply(value: serde_json::Value) -> *mut u8 {
    let text = value.to_string().into_bytes();
    let mut out = Vec::with_capacity(4 + text.len());
    out.extend_from_slice(&(text.len() as u32).to_le_bytes());
    out.extend_from_slice(&text);
    Box::into_raw(out.into_boxed_slice()) as *mut u8
}

/// What the container says about itself, before anything is decrypted.
///
/// # Safety
/// `ptr` must point at `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn sk_peek(ptr: *const u8, len: usize) -> *mut u8 {
    let bytes = core::slice::from_raw_parts(ptr, len);
    match fmt::peek(bytes) {
        Ok(header) => reply(json!({
            "ok": true,
            "encrypted": header.encrypted(),
            "thumbnails": header.flags().contains(fmt::Flags::THUMBNAILS),
            "originals": header.flags().contains(fmt::Flags::ORIGINALS),
            "blobs": header.blob_count,
            "body_len": header.body_len,
            "kdf": header.kdf.as_ref().map(|k| json!({
                "algorithm": "Argon2id",
                "m_kib": k.m_kib,
                "t": k.t,
                "p": k.p,
            })),
        })),
        Err(e) => reply(json!({ "ok": false, "error": e.to_string() })),
    }
}

/// Opens a container and returns what it holds.
///
/// # Safety
/// Both pointers must point at the number of readable bytes given for them. `pw_ptr` may
/// be null, for a container that is not encrypted.
#[no_mangle]
pub unsafe extern "C" fn sk_open(
    ptr: *const u8,
    len: usize,
    pw_ptr: *const u8,
    pw_len: usize,
) -> *mut u8 {
    let bytes = core::slice::from_raw_parts(ptr, len);
    let password = if pw_ptr.is_null() || pw_len == 0 {
        None
    } else {
        match core::str::from_utf8(core::slice::from_raw_parts(pw_ptr, pw_len)) {
            Ok(s) => Some(s),
            // Said without quoting the bytes back: an error is not a place to put
            // anything that came from a password field.
            Err(_) => return reply(json!({ "ok": false, "error": "the password is not valid text" })),
        }
    };

    match fmt::read(bytes, password) {
        Ok(opened) => {
            let project = &opened.project;
            let entries: Vec<serde_json::Value> = project
                .entries
                .iter()
                .map(|e| {
                    json!({
                        "path": e.path,
                        "size": e.size,
                        "taken": e.taken,
                        "blur": e.blur,
                        "kept": e.kept,
                        "thumbnail": e.thumbnail,
                        "sha": e.sha,
                    })
                })
                .collect();
            let groups: Vec<serde_json::Value> = project
                .groups
                .iter()
                .map(|g| json!({ "members": g.members, "suggested": g.suggested, "kind": g.kind }))
                .collect();
            let reply = reply(json!({
                "ok": true,
                "name": project.name,
                "created": project.created,
                "photos": project.entries.len(),
                "groups": groups,
                "roots": project.roots,
                "threshold": project.settings.similarity_threshold,
                "entries": entries,
                "blobs": opened.blobs.len(),
            }));
            OPEN.with(|slot| *slot.borrow_mut() = Some(opened));
            reply
        }
        // Including, and especially, the failures: a browser that opened a tampered file
        // anyway would be worse than one that could not open files at all.
        Err(e) => reply(json!({ "ok": false, "error": e.to_string() })),
    }
}

/// Drops the open container, and with it the decrypted project.
#[no_mangle]
pub extern "C" fn sk_forget() {
    OPEN.with(|slot| *slot.borrow_mut() = None);
}

/// Hands one blob back so the page can show a thumbnail.
///
/// Reads from the container already open, so it costs a memory copy rather than a key
/// derivation. Returns `[u32 length][bytes]`, freed with `sk_free`; a length of zero
/// means there is no such blob.
#[no_mangle]
pub extern "C" fn sk_blob(index: u32) -> *mut u8 {
    let bytes = OPEN.with(|slot| {
        slot.borrow()
            .as_ref()
            .and_then(|o| o.blobs.get(index as usize).cloned())
            .unwrap_or_default()
    });
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&bytes);
    Box::into_raw(out.into_boxed_slice()) as *mut u8
}

/// Times one Argon2id derivation at the given cost, in the browser.
///
/// The parameters in `skimrr-format`'s `Profile` were chosen from what this reports on
/// both targets rather than from a table, and it stays exported so the measurement can
/// be repeated on hardware nobody has tried yet. Returns `u32::MAX` for parameters
/// Argon2 refuses.
#[no_mangle]
pub extern "C" fn sk_bench_argon2(m_kib: u32, t: u32, p: u32) -> u32 {
    fmt::bench_argon2(m_kib, t, p)
}

# The `.skimrr` project format

A `.skimrr` file is one Skimrr project: what was scanned, what was found, what the user
decided, and — if asked for — the previews or the photographs themselves. It is meant to
be handed to someone on another operating system and opened there, with no server
involved at any point.

This document describes the format precisely enough to implement a reader, and explains
why each decision was made. Where the format has a limitation, it is stated here rather
than left to be discovered.

---

## 1. Shape

```
┌──────────────────────────────────────────────┐
│ magic          8 bytes   "SKIMRR\x1A\x00"    │
│ version        u16 LE    currently 1         │ ← the prefix, in the clear,
│ header_len     u32 LE                        │   and used verbatim as the
│ header         CBOR, header_len bytes        │   AEAD's associated data
├──────────────────────────────────────────────┤
│ body                                         │
│   plain:  the body as it is                  │
│   sealed: STREAM frames, each plaintext      │
│           frame followed by its 16-byte tag  │
└──────────────────────────────────────────────┘
```

The body, once decrypted, is:

```
manifest_len   u64 LE
manifest       deflate(CBOR(Project))
for each blob:
    blob_len   u64 LE
    blob       bytes
```

`0x1A` in the magic is the DOS end-of-file character, so a container piped into a text
tool stops there instead of spraying binary at a terminal. The trailing `0x00` keeps the
magic from ever being valid text somebody could paste.

## 2. The header

| field | type | meaning |
| --- | --- | --- |
| `flags` | u32 | `1` encrypted, `2` thumbnails, `4` originals |
| `compression` | enum | `0` none, `1` deflate — the manifest only |
| `kdf` | optional | present exactly when `ENCRYPTED` is set |
| `frame_len` | u32 | plaintext bytes per sealed frame (1 MiB) |
| `manifest_len` | u64 | compressed manifest length |
| `blob_count` | u32 | blobs after the manifest |
| `body_len` | u64 | total plaintext body length |
| `digest` | 32 bytes | SHA-256 of the plaintext body |

`kdf` carries the algorithm (only Argon2id is defined), `m_kib`, `t`, `p`, a 16-byte
salt, and the 19-byte STREAM nonce. Recording the cost rather than fixing it means a
future build can raise it without orphaning the projects written today.

The header is in the clear because it has to be: a reader must know a file is encrypted
before it can ask for a password, and must know what the file holds before the user
commits to opening it. It is also **authenticated** — see §4.

## 3. Cryptography

Nothing here is homemade. The construction is:

- **Argon2id** (`argon2` 0.5) turns the password into a 32-byte key. Salt from the
  operating system's generator, 16 bytes, per file.
- **XChaCha20-Poly1305** (`chacha20poly1305` 0.10) with **STREAM** framing
  (`EncryptorBE32` / `DecryptorBE32`) seals the body.
- **SHA-256** (`sha2` 0.10) gives an unencrypted container integrity against damage.

No primitive is reimplemented, and there is exactly one implementation of the format —
the same `skimrr-format` crate compiles for the desktop and for `wasm32-unknown-unknown`,
so a browser reader cannot drift from the desktop one.

### Why STREAM

A twenty-gigabyte project cannot be sealed as one message: it would have to be held in
memory whole, and a single tag over the lot means a reader learns the file is damaged
only after processing all of it. Chunking a file naively, though, introduces three
attacks that whole-file AEAD does not have — a frame can be dropped, duplicated, or
moved. STREAM answers all three by deriving each frame's nonce from the base nonce and
the frame's own index, and by marking the final frame as final:

- reordering fails, because position is authenticated;
- duplication fails, for the same reason;
- truncation fails, because the last frame carries a flag no earlier frame has.

`p = 1` in Argon2id is deliberate. This implementation is single-threaded and WebAssembly
has no threads, so extra lanes would buy work without parallelism — and hand an attacker
with real parallelism a structure to exploit.

### Cost, measured

One derivation, on an Apple-silicon laptop and in V8's WebAssembly:

| profile | memory | t | p | native | wasm |
| --- | --- | --- | --- | --- | --- |
| OWASP minimum | 19 MiB | 2 | 1 | 37 ms | 22–43 ms |
| **`Strong`** (default) | 128 MiB | 3 | 1 | 208 ms | 249–272 ms |
| `Maximum` | 256 MiB | 4 | 1 | 588 ms | 676–692 ms |

WebAssembly turned out to be about a third slower than native rather than the two-to
five-fold penalty that would have forced a compromise, so the default sits well above the
OWASP floor rather than at it. Memory is what defeats GPUs and custom hardware.
`Maximum` is not the default because 256 MiB is more than a constrained device or a busy
tab can always be given.

Re-measure on any machine with
`node crates/skimrr-wasm-demo/web/verify.mjs …`, which times all three.

## 4. Everything in the header is authenticated

The whole prefix — magic, version, length, and the CBOR header — is passed to the AEAD as
**associated data on every frame**. Three consequences:

- Editing any header field, including fields the reader does not consult, makes the very
  first frame fail to open. There is no "cosmetic" part of the header.
- **Frame boundaries are computed from the authenticated header, not read from the
  body.** There is no frame-length prefix in the payload, so "falsify a frame length" is
  not a detectable attack — it is not an expressible one. Falsifying a length means
  falsifying the header, and the header is authenticated.
- An attacker cannot shrink a file even by adjusting the header to match: the adjusted
  header breaks authentication before the shortened body is ever examined.

## 5. Reading order

A reader must do these in this order, and Skimrr's does:

1. Check the magic. Check the version, refusing anything higher rather than guessing.
2. Bound-check `header_len`, then parse the header, then validate every field against a
   ceiling — before any of them is used to allocate.
3. Check that the file's actual length is *exactly* what the header implies. Short means
   truncated; long means something was appended.
4. Derive the key. Authenticate every frame.
5. Only then decompress, with a ceiling on the output.
6. Only then deserialise the manifest.
7. Only then validate the manifest's own indices and paths.

Nothing attacker-controlled is acted upon before the step that could reject it has run.
A container that fails authentication is refused; there is no attempt to recover part of
it, because a partially-trusted file is not a thing that exists.

## 6. Paths

Every entry path is **relative to one of the project's roots**, with `/` separators
whatever wrote it. That relativity is the whole reason a project made on Windows opens on
Linux.

`safe_relative_path` refuses, on write and again on read, and again at the moment a path
becomes a real filename:

- empty, or longer than 1024 bytes
- containing a NUL, or a backslash (a separator on one platform, a legal filename
  character on another — which is exactly how a path that looks safe on Linux becomes
  `..\..\` on Windows)
- starting with `/`, or beginning with a drive letter (`C:`)
- any component that is empty, `.`, or `..`
- any component that is a Windows device name (`CON`, `NUL`, `COM1`…), with or without
  an extension, since Windows resolves those wherever they appear
- any component ending in a dot or a space, which Windows silently strips — so two
  distinct manifest entries could otherwise become one file on disk

A manifest is attacker-controlled *even when the cryptography passes*: a valid signature
over hostile data is still hostile data. So indices are range-checked, blob ownership is
checked to be unique, and group members are checked against the entries that exist.

## 7. Limits

Checked before anything is allocated from them:

| limit | value |
| --- | --- |
| header CBOR | 64 KiB |
| compressed manifest | 256 MiB |
| decompressed manifest | 512 MiB |
| blobs | 2,000,000 |
| body | 2 TiB |
| frame | 16 MiB |
| path | 1024 bytes |

The desktop reader adds one of its own: it will not open a container larger than 8 GiB,
because `read` is not streaming. Measured, the peak is about four times the container's
size rather than the twice that holding the file and its plaintext at once would suggest:
the compressed manifest, its inflated form and the deserialised structure are all live at
the same moment. That is a limit of the current API, not of the format.

## 8. What an unencrypted container does *not* promise

An unencrypted `.skimrr` has **integrity, not authenticity**. The SHA-256 catches damage
— a truncated copy, a bad transfer, a flipped bit on disk — and nothing more. Anyone who
can rewrite the body can recompute the digest, and the file will open.

This is not a defect to be fixed with a cleverer checksum. It is what "no key" means, and
the answer for a file that must not be forged is to encrypt it. There is a test named
after this fact so it cannot be quietly forgotten.

## 9. The password

- Never written to the file. Never written to disk. Never logged.
- Never placed in an error: no `Error` variant can carry one, and there is a test that
  formats every failure path and asserts the password does not appear.
- Borrowed, never copied into anything longer-lived; the derived key zeroes itself on
  drop; the desktop wipes its buffer as soon as a key has been derived from it; the
  browser glue overwrites the password's bytes in WebAssembly memory before releasing
  them.
- `WrongPasswordOrTampered` is deliberately one error and not two. An authenticated
  cipher cannot tell the difference, and pretending otherwise would invent a distinction
  that does not exist.

There is no recovery, no hint, and no escrow. A lost password means a lost file.

## 10. A `.skimrr` is only data

It is never executed. Nothing in it can name a library to load, a script to run, or a
command to invoke; there is no field with that shape and no code path that would use one.
The only things a container can cause are: bytes written under a path that passed §6, and
values shown in the interface.

## 11. What travels

| mode | contents | size |
| --- | --- | --- |
| findings only | paths, dates, digests, fingerprints, verdicts | ~340 bytes per photograph |
| with previews | + the small renditions | a few MB |
| with the photographs | + the files themselves | as large as what was scanned |

Photographs read out of the macOS Photos library are **left out and counted**: they have
no path under a scanned folder, so there would be nothing for another machine to find
again. Files whose names cannot be written safely on every platform are left out and
counted too, rather than failing the whole export over one filename.

The manifest is deflated; blobs are stored. Photographs are JPEG or HEIC already, and
compressing them again costs time to gain nothing.

## 12. Opening one

Given the container alone, Skimrr shows the findings. Given a folder as well, it resolves
each entry:

1. the relative path under that folder, then
2. by content — a size index of the folder narrows the field for free, and only
   candidates of exactly the right size are ever hashed.

So a photograph that was renamed or moved since the project was made is still found.
Anything that cannot be resolved is marked missing: its findings are shown, and there is
no file to act on.

When the container carries the originals, they are written under a folder the user
chooses. **A file already sitting at that path is never overwritten** — it is counted and
left alone.

## 13. Testing

The format is not considered validated because its primitives pass their own tests. The
battery is at the container level, in `crates/skimrr-format/src/container.rs`:

- **round trips** — plain, encrypted, with previews, with originals, multi-frame,
  relative-path relocation, and non-ASCII names
- **rejections** — a flipped bit at every byte of the header; header edits that still
  parse (the associated-data proof); unknown versions; inconsistent flags; implausible
  KDF parameters; truncation at *every* offset; a missing frame, an extra frame,
  reordered frames, a duplicated frame, a falsified frame length; blob counts that
  disagree with the body; a manifest claiming a blob twice or pointing past the end; path
  traversal on write and on read, including inside a correctly sealed container; absurd
  declared sizes and near-overflow lengths; trailing data; wrong and missing passwords;
  empty files and rubbish
- **a fuzz pass** of 8,000 mutated and random inputs, asserting the reader never panics
- **an honesty test** pinning §8, and one asserting no error can carry a password

The desktop layer has its own end-to-end tests, in the Skimrr application rather than
here, including a project carried to a different folder where two of the photographs have
been renamed, and the no-overwrite guarantee. Those cover how Skimrr *uses* a container;
everything about what a container *is* lives in this repository and is tested here.

The browser path is checked by `crates/skimrr-wasm-demo/web/verify.mjs`, which opens both
a plain and an encrypted container and confirms the tampering above is refused there too.

## 14. Version 1

`FORMAT_VERSION` is 1. A reader must refuse anything higher rather than guess: a future
version may move fields, and a hopeful parse of a layout it does not know is exactly how
a format starts silently corrupting projects.

Fields are CBOR maps keyed by name and optional fields carry `#[serde(default)]`, so a
version 1 reader tolerates a later writer adding fields — but only within version 1. The
application's own per-photograph data (dimensions, camera, coordinates, Bad Shot
measurements, dominant colour) rides in an opaque `extra` field the format deliberately
does not model, so Skimrr can add to it without the format changing at all. The dominant
colour is the worked example: it was added after this document was written, and not one
byte of the container changed.

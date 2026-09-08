# skimrr-format

The `.skimrr` container: what a Skimrr project is on disk, and the code that reads and
writes it.

This is published on purpose. Skimrr itself is closed, but a file format that claims to
encrypt your photographs is worth nothing if you have to take that claim on trust. The
whole point of [SPEC.md](SPEC.md) is that it is precise enough to implement a reader
from, and the point of this repository is that you can check the implementation against
it rather than believing a paragraph on a website.

## What is here

| | |
| --- | --- |
| [`crates/skimrr-format`](crates/skimrr-format) | the container: writing, reading, and every rejection |
| [`crates/skimrr-wasm-demo`](crates/skimrr-wasm-demo) | the same crate compiled to WebAssembly, and a script that runs the browser path from a terminal |
| [SPEC.md](SPEC.md) | the format, described precisely enough to implement, with the reasoning for each decision |

## The claims you can check here

**Nothing is homemade.** Argon2id derives the key, XChaCha20-Poly1305 with STREAM framing
seals the body, SHA-256 gives an unencrypted container integrity against damage. No
primitive is reimplemented. `crates/skimrr-format/src/crypto.rs` is where to look.

**There is one implementation, not two.** The same crate compiles for the desktop and for
`wasm32-unknown-unknown`, so the reader at [skimrr.com/open](https://skimrr.com/open)
cannot drift from the desktop one. `crates/skimrr-wasm-demo` is that build.

**The password is never stored, sent, or logged.** No `Error` variant can carry one, and
`no_error_can_carry_the_password` formats every failure path and asserts it does not
appear.

**An imported container is treated as hostile.** Path traversal, absurd declared sizes,
truncation, reordered and duplicated frames, decompression bombs: the battery is at the
container level, in `container.rs`, not only on the primitives underneath.

## Running the tests

```sh
cd crates/skimrr-format && cargo test
```

The browser path, without a browser:

```sh
cd crates/skimrr-wasm-demo
cargo build --release --target wasm32-unknown-unknown
node web/verify.mjs sample.skimrr encrypted.skimrr <password>
```

`verify.mjs` opens a plain and an encrypted container through the real WebAssembly module
and confirms that tampering is refused there too.

## Reading a `.skimrr` you were given

You do not need Skimrr for that. [skimrr.com/open](https://skimrr.com/open) runs this
module in your browser, and nothing is uploaded: the module imports exactly one function
from its host, the system random number generator. There is no network binding to switch
off because none was ever compiled in.

## Licence

Apache-2.0. A format is only portable if other people are allowed to implement it, and
this one is meant to be readable by tools that are not Skimrr.

The Skimrr application itself is a separate, closed repository. This crate is the part
where "trust us" would not be good enough.

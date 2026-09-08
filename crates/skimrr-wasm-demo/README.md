# The browser proof

One claim: **a `.skimrr` opens in a browser, with no server, using the same code the
desktop application uses.** This crate exists to demonstrate it and nothing else — it is
not the beginning of a web application.

## Building and running

```sh
rustup target add wasm32-unknown-unknown          # once
cargo build --target wasm32-unknown-unknown --release
```

That produces `target/wasm32-unknown-unknown/release/skimrr_wasm_demo.wasm` — about
260 KB, with **one import**: the platform's random number generator. No `wasm-bindgen`,
no `wasm-pack`, no npm. `cargo` and a browser are the whole toolchain.

To make a file to open:

```sh
cargo run -p skimrr-format --example make_sample -- sample.skimrr
cargo run -p skimrr-format --example make_sample -- locked.skimrr "correct horse battery staple"
```

Then serve this directory and open `web/index.html` — a server is needed only because
browsers will not `fetch` a `.wasm` over `file://`; the `.skimrr` itself is read from
the file you pick and never goes anywhere:

```sh
python3 -m http.server 8000     # then http://localhost:8000/web/
```

## Without a browser

`web/verify.mjs` runs the same module through the same glue under Node, which makes the
proof a thing that can be checked in a terminal rather than clicked:

```sh
node web/verify.mjs sample.skimrr locked.skimrr "correct horse battery staple"
```

It opens both containers, reads a thumbnail back out, and confirms that a wrong
password, a missing password, a flipped bit in the body, a flipped bit in the header, a
truncated file, appended bytes and outright rubbish are all refused. It finishes by
timing Argon2id at each profile on the engine in front of it.

## The interface

Five exports, plain C ABI, no bindings layer:

| export | what it does |
| --- | --- |
| `sk_alloc(len) -> ptr` | a buffer for the host to write a file into |
| `sk_dealloc(ptr, len)` | give it back |
| `sk_peek(ptr, len) -> ptr` | what the file says about itself, no key needed |
| `sk_open(ptr, len, pw, pw_len) -> ptr` | open it |
| `sk_blob(ptr, len, pw, pw_len, i) -> ptr` | one thumbnail, as bytes |
| `sk_free(ptr)` | release a returned buffer |

The two readers return `[u32 little-endian length][UTF-8 JSON]`. They never return null
and never trap: a failure comes back as `{"ok": false, "error": "…"}`, so the caller has
one path to handle instead of two.

## What this is not

It does not scan, cluster, or delete anything, and it holds no state between calls —
reading a thumbnail re-derives the key rather than keeping a decrypted project in memory
between clicks. It is a reader, and a deliberately small one.

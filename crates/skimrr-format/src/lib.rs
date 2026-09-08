//! The `.skimrr` portable project container.
//!
//! One file holds a whole Skimrr project: what was scanned, what was found, what the
//! user chose, and optionally the thumbnails or the photographs themselves. It is
//! designed to be handed to someone on another operating system and opened there, with
//! no server involved at any point.
//!
//! Everything in this crate is pure Rust and builds for `wasm32-unknown-unknown`, which
//! is a requirement rather than a nicety: the browser must run this exact code, so that
//! there is one implementation of the format and one of the cryptography rather than
//! two that can drift.

/// A tiny stand-in for the `bitflags` crate: three flags do not justify a dependency,
/// and `from_bits` returning `None` on an unknown bit is the whole reason it exists.
macro_rules! bitflags_lite {
    (
        $(#[$outer:meta])*
        pub struct $name:ident: $ty:ty {
            $(const $flag:ident = $value:expr;)*
        }
    ) => {
        $(#[$outer])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name(pub $ty);

        impl $name {
            $(pub const $flag: $name = $name($value);)*

            pub const ALL: $ty = 0 $(| $value)*;

            pub fn from_bits(bits: $ty) -> Option<Self> {
                (bits & !Self::ALL == 0).then_some($name(bits))
            }

            pub fn from_bits_truncate(bits: $ty) -> Self {
                $name(bits & Self::ALL)
            }

            pub fn contains(self, other: Self) -> bool {
                self.0 & other.0 == other.0
            }

            pub fn bits(self) -> $ty {
                self.0
            }
        }

        impl core::ops::BitOr for $name {
            type Output = Self;
            fn bitor(self, rhs: Self) -> Self {
                $name(self.0 | rhs.0)
            }
        }
    };
}

/// CBOR serialises a `[u8; N]` as an array of integers by default, which triples the
/// size and loses the fixed length on the way back. These keep them as byte strings.
macro_rules! byte_array_serde {
    ($module:ident, $len:expr) => {
        mod $module {
            use serde::{Deserialize, Deserializer, Serializer};

            pub fn serialize<S: Serializer>(v: &[u8; $len], s: S) -> Result<S::Ok, S::Error> {
                s.serialize_bytes(v)
            }

            pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; $len], D::Error> {
                let v = <serde_bytes::ByteBuf>::deserialize(d)?;
                <[u8; $len]>::try_from(v.as_ref()).map_err(|_| {
                    serde::de::Error::invalid_length(v.len(), &concat!(stringify!($len), " bytes"))
                })
            }
        }
    };
}

byte_array_serde!(serde_bytes_array16, 16);
byte_array_serde!(serde_bytes_array19, 19);
byte_array_serde!(serde_bytes_array32, 32);

/// Where randomness comes from in a browser.
///
/// The crate needs an operating system generator to make a salt and a nonce, and
/// WebAssembly has none of its own. Rather than pull in a binding layer for it, the host
/// supplies one function and the module imports exactly that — so the complete list of
/// things this module can reach outside itself is: the system random number generator.
///
/// A page that only reads containers still has to provide it, and it is three lines:
///
/// ```js
/// const imports = { env: { skimrr_random: (ptr, len) =>
///   crypto.getRandomValues(new Uint8Array(memory.buffer, ptr, len)) && 0 } };
/// ```
#[cfg(target_arch = "wasm32")]
mod host_random {
    extern "C" {
        /// Fills `len` bytes at `ptr`. Returns zero on success.
        fn skimrr_random(ptr: *mut u8, len: usize) -> i32;
    }

    fn fill(dest: &mut [u8]) -> Result<(), getrandom::Error> {
        // Safety: `dest` is a live, uniquely borrowed slice for the whole call.
        match unsafe { skimrr_random(dest.as_mut_ptr(), dest.len()) } {
            0 => Ok(()),
            // A host that cannot produce randomness must fail loudly. Falling back to
            // anything weaker here would silently turn a strong container into a
            // forgeable one, which is the worst possible way to be helpful.
            _ => Err(getrandom::Error::UNSUPPORTED),
        }
    }

    getrandom::register_custom_getrandom!(fill);
}

mod container;
mod crypto;
mod error;
mod header;
mod project;

pub use container::{peek, read, write, Contents, Opened, FRAME_LEN};
pub use crypto::{forget, Profile};
pub use error::{Error, Result};
pub use header::{Compression, Flags, Header, Kdf, FORMAT_VERSION, MAGIC};
pub use project::{safe_relative_path, Entry, Group, Project, Settings, MAX_PATH_LEN};

#[cfg(test)]
mod verify_construction {
    use argon2::{Algorithm, Argon2, Params, Version};
    use chacha20poly1305::{
        aead::stream::{DecryptorBE32, EncryptorBE32},
        KeyInit, XChaCha20Poly1305,
    };

    fn derive(password: &[u8], salt: &[u8]) -> [u8; 32] {
        let params = Params::new(19 * 1024, 2, 1, Some(32)).unwrap();
        let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = [0u8; 32];
        a.hash_password_into(password, salt, &mut key).unwrap();
        key
    }

    /// Argon2id must be the variant actually used, and the same inputs must give the
    /// same key on every machine — the whole portability claim rests on it.
    #[test]
    fn argon2id_is_deterministic_and_salt_dependent() {
        let a = derive(b"correct horse", b"0123456789abcdef");
        let b = derive(b"correct horse", b"0123456789abcdef");
        let c = derive(b"correct horse", b"fedcba9876543210");
        let d = derive(b"wrong horse", b"0123456789abcdef");
        assert_eq!(a, b, "same password and salt, same key");
        assert_ne!(a, c, "a different salt must give a different key");
        assert_ne!(a, d, "a different password must give a different key");
    }

    /// The framed construction: STREAM with a big-endian 32-bit counter, which is what
    /// lets a twenty-gigabyte project be sealed without ever holding it in memory.
    #[test]
    fn framed_aead_round_trips() {
        let key = derive(b"pw", b"0123456789abcdef");
        // XChaCha20 takes a 24-byte nonce; BE32 spends 5 of them on the counter and
        // the last-frame flag, so the caller supplies 19.
        let nonce = [7u8; 19];
        let mut enc = EncryptorBE32::from_aead(XChaCha20Poly1305::new(&key.into()), &nonce.into());
        let f1 = enc.encrypt_next(b"first frame".as_slice()).unwrap();
        let f2 = enc.encrypt_last(b"second frame".as_slice()).unwrap();

        let mut dec = DecryptorBE32::from_aead(XChaCha20Poly1305::new(&key.into()), &nonce.into());
        assert_eq!(dec.decrypt_next(f1.as_slice()).unwrap(), b"first frame");
        assert_eq!(dec.decrypt_last(f2.as_slice()).unwrap(), b"second frame");
    }

    /// Every failure mode the format has to detect, checked against the primitive
    /// itself before any of it is relied upon further up.
    #[test]
    fn tampering_truncation_and_reordering_all_fail() {
        let key = derive(b"pw", b"0123456789abcdef");
        let nonce = [7u8; 19];
        let seal = || {
            let mut e =
                EncryptorBE32::from_aead(XChaCha20Poly1305::new(&key.into()), &nonce.into());
            let a = e.encrypt_next(b"aaaa".as_slice()).unwrap();
            let b = e.encrypt_last(b"bbbb".as_slice()).unwrap();
            (a, b)
        };
        let open = |frames: &[Vec<u8>]| -> Result<(), ()> {
            let mut d =
                DecryptorBE32::from_aead(XChaCha20Poly1305::new(&key.into()), &nonce.into());
            for f in &frames[..frames.len() - 1] {
                d.decrypt_next(f.as_slice()).map_err(|_| ())?;
            }
            d.decrypt_last(frames[frames.len() - 1].as_slice()).map_err(|_| ())?;
            Ok(())
        };

        let (a, b) = seal();
        assert!(open(&[a.clone(), b.clone()]).is_ok(), "the untouched pair opens");

        let mut flipped = a.clone();
        flipped[0] ^= 1;
        assert!(open(&[flipped, b.clone()]).is_err(), "a flipped bit must fail");

        // Dropping the final frame: the last one carries a flag, so a truncated stream
        // cannot pass as a complete one.
        assert!(open(std::slice::from_ref(&a)).is_err(), "truncation must fail");

        // Swapping frames: the counter is authenticated, so order is not negotiable.
        assert!(open(&[b, a]).is_err(), "reordering must fail");

        let wrong = derive(b"not the password", b"0123456789abcdef");
        let (a2, b2) = seal();
        let mut d = DecryptorBE32::from_aead(XChaCha20Poly1305::new(&wrong.into()), &nonce.into());
        assert!(d.decrypt_next(a2.as_slice()).is_err(), "a wrong password must fail");
        let _ = b2;
    }
}

#[cfg(test)]
mod bench {
    use argon2::{Algorithm, Argon2, Params, Version};

    #[test]
    #[ignore = "benchmark"]
    fn argon2_cost() {
        // m in KiB, t passes, p lanes
        for (m, t, p, label) in [
            (19 * 1024, 2, 1, "OWASP minimum"),
            (128 * 1024, 3, 1, "Strong"),
            (256 * 1024, 4, 1, "Maximum"),
        ] {
            let params = Params::new(m, t, p, Some(32)).unwrap();
            let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let mut key = [0u8; 32];
            let start = std::time::Instant::now();
            a.hash_password_into(b"a fairly long passphrase", b"0123456789abcdef", &mut key)
                .unwrap();
            eprintln!(
                "BENCH m={:>4} MiB t={} p={}  {:>8.0} ms  {}",
                m / 1024,
                t,
                p,
                start.elapsed().as_secs_f64() * 1000.0,
                label
            );
        }
    }
}

/// Times one key derivation, so the cost of a profile can be measured on the machine
/// that will actually pay it.
///
/// Returns a byte of the derived key, which is what stops the work being optimised away.
/// Timing is the caller's job: WebAssembly has no clock without asking its host for one.
pub fn bench_argon2(m_kib: u32, t: u32, p: u32) -> u32 {
    use argon2::{Algorithm, Argon2, Params, Version};
    let Ok(params) = Params::new(m_kib, t, p, Some(32)) else {
        return u32::MAX;
    };
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    if a.hash_password_into(b"a fairly long passphrase", b"0123456789abcdef", &mut key).is_err() {
        return u32::MAX;
    }
    key[0] as u32
}

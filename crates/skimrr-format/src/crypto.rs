use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::stream::{DecryptorBE32, EncryptorBE32},
    KeyInit, XChaCha20Poly1305,
};
use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};
use crate::header::{Kdf, ARGON2ID};

/// How hard a password is to attack, chosen by measurement rather than by taste.
///
/// Timings for one derivation, on an Apple-silicon laptop and in V8's WebAssembly:
///
/// | profile          | memory  | t | p | native | wasm   |
/// |------------------|---------|---|---|--------|--------|
/// | (OWASP minimum)  |  19 MiB | 2 | 1 |  37 ms |  43 ms |
/// | `Strong`         | 128 MiB | 3 | 1 | 208 ms | 272 ms |
/// | `Maximum`        | 256 MiB | 4 | 1 | 588 ms | 676 ms |
///
/// WebAssembly turned out to be only about a third slower than native, not the two-to
/// five-fold penalty that would have forced a compromise, so the default is well above
/// the OWASP floor rather than at it: memory is what defeats GPUs and custom hardware.
///
/// `p = 1` deliberately. This Argon2 is single-threaded and WebAssembly has no threads,
/// so extra lanes would buy work without parallelism — and hand an attacker with real
/// parallelism a structure to exploit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// 128 MiB — six and a half times the OWASP minimum, and still under a third of a
    /// second to unlock in a browser.
    Strong,
    /// 256 MiB. Twice the work, and twice the memory an ordinary tab must be allowed
    /// to allocate: strong, but it can fail on a constrained device, which is why it
    /// is not the default.
    Maximum,
    /// The cheapest derivation `Header::validate` will accept, so that a few hundred
    /// tamper-rejection tests cost seconds rather than minutes. Compiled out of every
    /// shipping build: a `#[cfg(test)]` variant cannot be named, let alone written to a
    /// file, by anything a user runs.
    #[cfg(test)]
    Test,
}

impl Profile {
    fn params(self) -> (u32, u32, u32) {
        match self {
            Profile::Strong => (128 * 1024, 3, 1),
            Profile::Maximum => (256 * 1024, 4, 1),
            #[cfg(test)]
            Profile::Test => (8 * 1024, 1, 1),
        }
    }

    /// A fresh key derivation description: new random salt, new random stream nonce.
    ///
    /// Both come from the operating system's generator through `OsRng`. A salt reused
    /// across projects would let one cracking effort cover them all; a nonce reused
    /// under the same key would break the cipher outright.
    pub fn new_kdf(self) -> Kdf {
        let (m_kib, t, p) = self.params();
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 19];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        Kdf { algorithm: ARGON2ID, m_kib, t, p, salt, nonce }
    }
}

/// A derived key, wiped from memory when it goes out of scope.
pub type Key = Zeroizing<[u8; 32]>;

/// Turns a password into the key the container is sealed with.
///
/// The password is borrowed and never copied into a longer-lived structure, never
/// written anywhere, and never placed in an error: `Error` has no variant that can
/// carry it. The key it produces zeroes itself on drop.
pub fn derive_key(password: &str, kdf: &Kdf) -> Result<Key> {
    if kdf.algorithm != ARGON2ID {
        return Err(Error::MalformedHeader("unknown key derivation"));
    }
    let params = Params::new(kdf.m_kib, kdf.t, kdf.p, Some(32))
        .map_err(|_| Error::MalformedHeader("implausible key derivation cost"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password.as_bytes(), &kdf.salt, key.as_mut())
        // A failure here is a parameter problem, never a password problem, and saying
        // so plainly avoids leaking anything about the password itself.
        .map_err(|_| Error::MalformedHeader("key derivation failed"))?;
    Ok(key)
}

/// Bytes added to each frame by its authentication tag.
pub const TAG_LEN: usize = 16;

/// Seals a body a frame at a time.
///
/// STREAM, with a big-endian 32-bit counter: each frame is encrypted under a nonce
/// derived from the base nonce and its own index, and the final frame is marked as
/// final. That is what makes the three attacks on a chunked format fail — a frame
/// cannot be dropped, duplicated, or moved, because its position is authenticated
/// along with its contents.
///
/// The header is passed as associated data on every frame, so editing so much as a
/// flag in the clear-text header makes the very first frame fail to open.
pub struct Sealer {
    inner: Option<EncryptorBE32<XChaCha20Poly1305>>,
    aad: Vec<u8>,
}

impl Sealer {
    pub fn new(key: &Key, kdf: &Kdf, aad: Vec<u8>) -> Self {
        let cipher = XChaCha20Poly1305::new(key.as_ref().into());
        Sealer { inner: Some(EncryptorBE32::from_aead(cipher, &kdf.nonce.into())), aad }
    }

    pub fn frame(&mut self, plain: &[u8]) -> Result<Vec<u8>> {
        let enc = self.inner.as_mut().ok_or(Error::MalformedBody("stream already finished"))?;
        enc.encrypt_next(chacha20poly1305::aead::Payload { msg: plain, aad: &self.aad })
            .map_err(|_| Error::WrongPasswordOrTampered)
    }

    pub fn last(mut self, plain: &[u8]) -> Result<Vec<u8>> {
        let enc = self.inner.take().ok_or(Error::MalformedBody("stream already finished"))?;
        enc.encrypt_last(chacha20poly1305::aead::Payload { msg: plain, aad: &self.aad })
            .map_err(|_| Error::WrongPasswordOrTampered)
    }
}

/// Opens a sealed body a frame at a time. Mirrors `Sealer` exactly, including the
/// associated data, so a mismatch anywhere surfaces as an authentication failure
/// rather than as plausible-looking rubbish.
pub struct Opener {
    inner: Option<DecryptorBE32<XChaCha20Poly1305>>,
    aad: Vec<u8>,
}

impl Opener {
    pub fn new(key: &Key, kdf: &Kdf, aad: Vec<u8>) -> Self {
        let cipher = XChaCha20Poly1305::new(key.as_ref().into());
        Opener { inner: Some(DecryptorBE32::from_aead(cipher, &kdf.nonce.into())), aad }
    }

    pub fn frame(&mut self, sealed: &[u8]) -> Result<Vec<u8>> {
        let dec = self.inner.as_mut().ok_or(Error::MalformedBody("stream already finished"))?;
        dec.decrypt_next(chacha20poly1305::aead::Payload { msg: sealed, aad: &self.aad })
            .map_err(|_| Error::WrongPasswordOrTampered)
    }

    pub fn last(mut self, sealed: &[u8]) -> Result<Vec<u8>> {
        let dec = self.inner.take().ok_or(Error::MalformedBody("stream already finished"))?;
        dec.decrypt_last(chacha20poly1305::aead::Payload { msg: sealed, aad: &self.aad })
            .map_err(|_| Error::WrongPasswordOrTampered)
    }
}

/// SHA-256 of a plaintext body.
///
/// Integrity, not authenticity, and only used on unencrypted containers. Anyone who can
/// rewrite the body can recompute this; what it catches is damage — a truncated copy, a
/// bad transfer, a flipped bit on disk. The documentation is explicit that an
/// unencrypted `.skimrr` carries no protection against a deliberate edit, because
/// without a key there is none to be had.
pub fn digest(body: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(body);
    h.finalize().into()
}

/// Wipes a password buffer the caller is done with.
pub fn forget(mut password: String) {
    password.zeroize();
}

use core::fmt;

/// Everything that can be wrong with a `.skimrr` file.
///
/// Deliberately specific about *what* failed and deliberately silent about the secret:
/// no variant carries a password, a derived key, or any plaintext. `WrongPasswordOrTampered`
/// is one variant rather than two on purpose — an authenticated cipher cannot tell the
/// difference, and pretending otherwise would invent a distinction that does not exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Not a `.skimrr` file at all.
    NotSkimrr,
    /// A container written by a newer Skimrr than this one.
    UnsupportedVersion { found: u16, supported: u16 },
    /// The header does not describe a container this code can act on: a length that
    /// cannot be true, a flag combination with no meaning, a missing key derivation
    /// on a file that claims to be encrypted.
    MalformedHeader(&'static str),
    /// Structurally intact but not what it claims: a frame missing, a length that does
    /// not add up, bytes left over.
    MalformedBody(&'static str),
    /// Authentication failed. The password is wrong, or the file was altered — and by
    /// construction there is no way to know which.
    WrongPasswordOrTampered,
    /// An unencrypted container whose contents do not match the digest it carries.
    Corrupted,
    /// A manifest entry naming a path that must never be written: absolute, escaping
    /// upwards, or otherwise not a plain relative name.
    UnsafePath,
    /// The file asks for more memory than any real project would need.
    TooLarge { limit: u64 },
    /// The manifest itself does not deserialise.
    MalformedManifest,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotSkimrr => write!(f, "not a Skimrr project file"),
            Error::UnsupportedVersion { found, supported } => write!(
                f,
                "this project was made by a newer Skimrr (format {found}, this build reads up to {supported})"
            ),
            Error::MalformedHeader(why) => write!(f, "the project header is malformed: {why}"),
            Error::MalformedBody(why) => write!(f, "the project data is malformed: {why}"),
            Error::WrongPasswordOrTampered => {
                write!(f, "wrong password, or the file has been altered")
            }
            Error::Corrupted => write!(f, "the file is damaged and cannot be trusted"),
            Error::UnsafePath => write!(f, "the project names a file path that is not safe to use"),
            Error::TooLarge { limit } => {
                write!(f, "the file declares more data than is plausible (limit {limit} bytes)")
            }
            Error::MalformedManifest => write!(f, "the project data could not be read"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;

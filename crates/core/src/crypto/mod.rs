pub mod aes_gcm;
pub mod ecies;
pub mod ed25519;
pub mod kdf;
pub mod key_derivation;
pub mod key_ring;
pub mod master_secret;
pub mod password;
pub mod session;

use std::sync::atomic::{AtomicU32, Ordering};

use argon2::Argon2;

use crate::error::CryptoError;

/// Argon2id cost parameters, chosen at runtime.
///
/// These used to be a compile-time choice behind the `test-crypto` cargo
/// feature, which cargo's feature unification could switch on for a
/// production build. They are now ordinary values: the server installs
/// [`Argon2Params::PRODUCTION`] (or whatever `AGTCRDN_ARGON2_*` says) at
/// startup, and the test harness installs [`Argon2Params::FAST`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    /// Memory cost in kibibytes.
    pub m_cost_kib: u32,
    /// Number of passes.
    pub t_cost: u32,
    /// Degree of parallelism (lanes).
    pub p_cost: u32,
}

impl Argon2Params {
    /// 64 MiB, 3 iterations, 4 lanes.
    pub const PRODUCTION: Self = Self {
        m_cost_kib: 65536,
        t_cost: 3,
        p_cost: 4,
    };

    /// 256 KiB, 1 iteration, 1 lane: fast enough for a test suite, and never
    /// a default.
    pub const FAST: Self = Self {
        m_cost_kib: 256,
        t_cost: 1,
        p_cost: 1,
    };

    /// Validate the triple against Argon2's own rules.
    pub fn new(m_cost_kib: u32, t_cost: u32, p_cost: u32) -> Result<Self, CryptoError> {
        let candidate = Self {
            m_cost_kib,
            t_cost,
            p_cost,
        };
        candidate.to_params()?;
        Ok(candidate)
    }

    fn to_params(self) -> Result<argon2::Params, CryptoError> {
        argon2::Params::new(self.m_cost_kib, self.t_cost, self.p_cost, None).map_err(|e| {
            CryptoError::KeyDerivation(format!(
                "invalid Argon2 parameters (m={} KiB, t={}, p={}): {e}",
                self.m_cost_kib, self.t_cost, self.p_cost
            ))
        })
    }

    /// Build an Argon2id instance with these parameters. Falls back to
    /// [`Argon2Params::PRODUCTION`] if the triple is somehow invalid, so a
    /// misconfiguration can never weaken hashing below production cost.
    pub fn build<'a>(self) -> Argon2<'a> {
        let params = self.to_params().unwrap_or_else(|e| {
            tracing::error!(error = %e, "falling back to production Argon2 parameters");
            Self::PRODUCTION
                .to_params()
                .expect("production Argon2 parameters are valid")
        });
        Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
    }
}

impl Default for Argon2Params {
    fn default() -> Self {
        // Core's own unit tests hash passwords by the dozen; `cfg(test)` is
        // set only when this crate is compiled as a test binary and, unlike
        // a cargo feature, cannot be turned on by a dependent crate.
        #[cfg(test)]
        {
            Self::FAST
        }
        #[cfg(not(test))]
        {
            Self::PRODUCTION
        }
    }
}

/// Installed parameters. `0` memory cost means "nothing installed", in which
/// case [`Argon2Params::default`] applies.
static INSTALLED_M_COST: AtomicU32 = AtomicU32::new(0);
static INSTALLED_T_COST: AtomicU32 = AtomicU32::new(0);
static INSTALLED_P_COST: AtomicU32 = AtomicU32::new(0);

/// Install the Argon2id parameters every hash in this process uses.
///
/// Called once at startup by the server binary and by the test harness.
pub fn install_argon2_params(params: Argon2Params) {
    INSTALLED_T_COST.store(params.t_cost, Ordering::Relaxed);
    INSTALLED_P_COST.store(params.p_cost, Ordering::Relaxed);
    // Written last: it is the flag the reader checks.
    INSTALLED_M_COST.store(params.m_cost_kib, Ordering::Relaxed);
}

/// The parameters currently in force.
pub fn argon2_params() -> Argon2Params {
    let m_cost_kib = INSTALLED_M_COST.load(Ordering::Relaxed);
    if m_cost_kib == 0 {
        return Argon2Params::default();
    }
    Argon2Params {
        m_cost_kib,
        t_cost: INSTALLED_T_COST.load(Ordering::Relaxed),
        p_cost: INSTALLED_P_COST.load(Ordering::Relaxed),
    }
}

/// Build an Argon2id instance with the parameters in force.
pub(crate) fn build_argon2<'a>() -> Argon2<'a> {
    argon2_params().build()
}

/// Trait for encrypting/decrypting secret values at rest.
pub trait SecretEncryptor: Send + Sync {
    /// Encrypt plaintext with additional authenticated data (AAD).
    /// Returns (ciphertext, nonce).
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError>;

    /// Decrypt ciphertext given its nonce and additional authenticated data (AAD).
    fn decrypt(&self, ciphertext: &[u8], nonce: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_parameters_are_the_hardened_ones() {
        assert_eq!(Argon2Params::PRODUCTION.m_cost_kib, 65536);
        assert_eq!(Argon2Params::PRODUCTION.t_cost, 3);
        assert_eq!(Argon2Params::PRODUCTION.p_cost, 4);
    }

    #[test]
    fn invalid_parameters_are_rejected_at_construction() {
        assert!(Argon2Params::new(65536, 3, 4).is_ok());
        assert!(Argon2Params::new(0, 3, 4).is_err(), "zero memory cost");
        assert!(Argon2Params::new(65536, 0, 4).is_err(), "zero iterations");
        assert!(Argon2Params::new(65536, 3, 0).is_err(), "zero lanes");
    }

    #[test]
    fn installed_parameters_are_what_hashing_uses() {
        let before = argon2_params();
        install_argon2_params(Argon2Params::FAST);
        assert_eq!(argon2_params(), Argon2Params::FAST);
        install_argon2_params(before);
        assert_eq!(argon2_params(), before);
    }
}

mod aws_sigv4;

pub use aws_sigv4::{aws_sigv4, infer_aws_region_service};

use base64::Engine as _;

use super::TransformOutput;

/// Identity transform: returns the secret as-is.
pub fn identity(secret: &str) -> TransformOutput {
    secret.to_string().into()
}

/// Basic-auth transform: expects "user:pass" format, returns base64-encoded.
pub fn basic_auth(secret: &str) -> TransformOutput {
    let encoded = base64::engine::general_purpose::STANDARD.encode(secret.as_bytes());
    format!("Basic {}", encoded).into()
}

/// Bearer transform: prefixes the secret with "Bearer ".
pub fn bearer(secret: &str) -> TransformOutput {
    format!("Bearer {}", secret).into()
}

#[cfg(test)]
mod tests;

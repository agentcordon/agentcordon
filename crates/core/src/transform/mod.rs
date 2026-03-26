use std::collections::HashMap;

pub mod builtins;
pub mod rhai_engine;

/// Maximum size of a Rhai transform script in bytes (64 KB).
pub const MAX_TRANSFORM_SCRIPT_SIZE: usize = 65_536;

/// Output from a transform execution.
/// `value` is the primary output (replaces the placeholder).
/// `extra_headers` are additional headers to inject into the proxy request.
#[derive(Debug, Clone, Default)]
pub struct TransformOutput {
    pub value: String,
    pub extra_headers: HashMap<String, String>,
}

impl From<String> for TransformOutput {
    fn from(value: String) -> Self {
        Self {
            value,
            extra_headers: HashMap::new(),
        }
    }
}

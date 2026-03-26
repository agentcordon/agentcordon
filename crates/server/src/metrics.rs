//! Prometheus metrics setup and HTTP handler.

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

/// Initialize the Prometheus metrics recorder and return the handle
/// for rendering metrics output.
pub fn setup_metrics() -> PrometheusHandle {
    let builder = PrometheusBuilder::new();
    builder
        .install_recorder()
        .expect("failed to install metrics recorder")
}

/// Create a no-op `PrometheusHandle` suitable for tests.
///
/// Builds a recorder without installing it as the global recorder, so
/// multiple test threads can each obtain their own handle without
/// conflicting with each other.
#[doc(hidden)]
pub fn test_handle() -> PrometheusHandle {
    let recorder = PrometheusBuilder::new().build_recorder();
    recorder.handle()
}

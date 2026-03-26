//! SSE endpoint for real-time UI event streaming.
//!
//! `GET /api/v1/events/ui` — requires session cookie authentication.
//! Streams `UiEvent`s to the browser as Server-Sent Events.
//! Limited to 2 concurrent connections per user to prevent connection leaks.

use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::{
    extract::State,
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse,
    },
    routing::get,
    Router,
};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::{Stream, StreamExt};

use crate::events::SseConnectionGuard;
use crate::extractors::AuthenticatedUser;
use crate::response::ApiError;
use crate::state::AppState;

/// Register SSE routes.
pub fn routes() -> Router<AppState> {
    Router::new().route("/events/ui", get(ui_event_stream))
}

/// A stream wrapper that holds an [`SseConnectionGuard`] alive for the
/// lifetime of the inner stream. When the client disconnects and the stream
/// is dropped, the guard decrements the connection count.
struct GuardedStream<S> {
    inner: Pin<Box<S>>,
    _guard: SseConnectionGuard,
}

impl<S: Stream> Stream for GuardedStream<S> {
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

/// GET /api/v1/events/ui — SSE stream of UI events.
///
/// Requires a valid session cookie. Returns `text/event-stream`.
/// Each event has `event: <type>` and `data: <json>`.
/// A heartbeat comment is sent every 30 seconds to keep the connection alive.
///
/// Limited to 2 concurrent SSE connections per user. Returns 429 if exceeded.
async fn ui_event_stream(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    let user_id = auth.user.id.0;

    // Enforce per-user connection limit
    let guard = state.sse_tracker.try_acquire(user_id).map_err(|()| {
        tracing::warn!(%user_id, "SSE connection limit exceeded");
        ApiError::TooManyRequests("too many SSE connections".to_string())
    })?;

    let rx = state.ui_event_bus.subscribe();
    let stream = BroadcastStream::new(rx);

    let event_stream = stream.filter_map(|result| match result {
        Ok(ui_event) => {
            let event_type = ui_event.event_type().to_string();
            match serde_json::to_string(&ui_event) {
                Ok(data) => Some(Ok::<_, Infallible>(
                    Event::default().event(event_type).data(data),
                )),
                Err(_) => None,
            }
        }
        // Lagged — some events were dropped because client is too slow.
        // Continue streaming from current position.
        Err(_) => None,
    });

    // Wrap stream so the guard lives as long as the SSE connection.
    let guarded = GuardedStream {
        inner: Box::pin(event_stream),
        _guard: guard,
    };

    Ok(Sse::new(guarded).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(30))
            .text("heartbeat"),
    ))
}

mod crud;
mod testing;

use axum::{
    routing::{get, post},
    Router,
};

use crate::state::AppState;

use crud::{
    create_policy, delete_policy, get_policy, get_schema, get_schema_reference, list_policies,
    update_policy, validate_policy,
};
use testing::test_policy;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/policies", post(create_policy).get(list_policies))
        .route("/policies/schema", get(get_schema))
        .route("/policies/schema/reference", get(get_schema_reference))
        .route("/policies/test", post(test_policy))
        .route("/policies/validate", post(validate_policy))
        .route(
            "/policies/{id}",
            get(get_policy).put(update_policy).delete(delete_policy),
        )
}

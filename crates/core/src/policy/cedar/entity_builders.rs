use std::collections::{HashMap, HashSet};

use cedar_policy::{Context, Entity, EntityId, EntityTypeName, EntityUid, RestrictedExpression};

use crate::domain::user::{User, UserId};
use crate::domain::workspace::Workspace;
use crate::error::PolicyError;

use super::super::{actions, entities, PolicyContext, PolicyResource, PolicyServer};
use super::CedarPolicyEngine;

impl CedarPolicyEngine {
    // -----------------------------------------------------------------------
    // Workspace entity helpers
    // -----------------------------------------------------------------------

    /// Build a Cedar `EntityUid` for an `AgentCordon::Workspace`.
    pub(super) fn workspace_uid(workspace: &Workspace) -> EntityUid {
        let type_name: EntityTypeName =
            entities::WORKSPACE.parse().expect("valid entity type name");
        let eid = EntityId::new(workspace.id.0.to_string());
        EntityUid::from_type_name_and_id(type_name, eid)
    }

    /// Build a Cedar `Entity` for a workspace principal.
    pub(super) fn build_workspace_entity(workspace: &Workspace) -> Result<Entity, PolicyError> {
        let uid = Self::workspace_uid(workspace);

        let tags_set = RestrictedExpression::new_set(
            workspace
                .tags
                .iter()
                .map(|t| RestrictedExpression::new_string(t.clone())),
        );

        let mut attrs: HashMap<String, RestrictedExpression> = HashMap::from([
            (
                "name".to_string(),
                RestrictedExpression::new_string(workspace.name.clone()),
            ),
            (
                "enabled".to_string(),
                RestrictedExpression::new_bool(workspace.enabled),
            ),
            ("tags".to_string(), tags_set),
        ]);

        // Include owner reference if the workspace has an owner_id.
        if let Some(ref owner_id) = workspace.owner_id {
            attrs.insert(
                "owner".to_string(),
                RestrictedExpression::new_entity_uid(Self::user_uid_from_id(owner_id)),
            );
        }

        // Include parent reference if the workspace has a parent.
        if let Some(ref parent_id) = workspace.parent_id {
            let ws_type: EntityTypeName =
                entities::WORKSPACE.parse().expect("valid entity type name");
            let parent_eid = EntityId::new(parent_id.0.to_string());
            let parent_uid = EntityUid::from_type_name_and_id(ws_type, parent_eid);
            attrs.insert(
                "parent".to_string(),
                RestrictedExpression::new_entity_uid(parent_uid),
            );
        }

        Entity::new(uid, attrs, HashSet::new())
            .map_err(|e| PolicyError::Evaluation(format!("workspace entity: {e}")))
    }

    // -----------------------------------------------------------------------
    // User entity helpers
    // -----------------------------------------------------------------------

    /// Build a Cedar `EntityUid` for an `AgentCordon::User`.
    pub(super) fn user_uid(user: &User) -> EntityUid {
        let type_name: EntityTypeName = entities::USER.parse().expect("valid entity type name");
        let eid = EntityId::new(user.id.0.to_string());
        EntityUid::from_type_name_and_id(type_name, eid)
    }

    /// Build an `EntityUid` for a user by ID.
    fn user_uid_from_id(user_id: &UserId) -> EntityUid {
        let type_name: EntityTypeName = entities::USER.parse().expect("valid entity type name");
        let eid = EntityId::new(user_id.0.to_string());
        EntityUid::from_type_name_and_id(type_name, eid)
    }

    /// Build a Cedar `Entity` for a user principal.
    pub(super) fn build_user_entity(user: &User) -> Result<Entity, PolicyError> {
        let uid = Self::user_uid(user);

        let role_str = match user.role {
            crate::domain::user::UserRole::Admin => "admin",
            crate::domain::user::UserRole::Operator => "operator",
            crate::domain::user::UserRole::Viewer => "viewer",
        };

        let attrs: HashMap<String, RestrictedExpression> = HashMap::from([
            (
                "name".to_string(),
                RestrictedExpression::new_string(user.username.clone()),
            ),
            (
                "role".to_string(),
                RestrictedExpression::new_string(role_str.to_string()),
            ),
            (
                "enabled".to_string(),
                RestrictedExpression::new_bool(user.enabled),
            ),
            (
                "is_root".to_string(),
                RestrictedExpression::new_bool(user.is_root),
            ),
        ]);

        Entity::new(uid, attrs, HashSet::new())
            .map_err(|e| PolicyError::Evaluation(format!("user entity: {e}")))
    }

    // -----------------------------------------------------------------------
    // Server entity helpers
    // -----------------------------------------------------------------------

    /// Build a Cedar `EntityUid` for an `AgentCordon::Server`.
    pub(super) fn server_uid(server: &PolicyServer) -> EntityUid {
        let type_name: EntityTypeName = entities::SERVER.parse().expect("valid entity type name");
        let eid = EntityId::new(server.id.clone());
        EntityUid::from_type_name_and_id(type_name, eid)
    }

    /// Build a Cedar `Entity` for a server principal.
    pub(super) fn build_server_entity(server: &PolicyServer) -> Result<Entity, PolicyError> {
        let uid = Self::server_uid(server);

        let tags_set = RestrictedExpression::new_set(
            server
                .tags
                .iter()
                .map(|t| RestrictedExpression::new_string(t.clone())),
        );

        let attrs: HashMap<String, RestrictedExpression> = HashMap::from([
            (
                "name".to_string(),
                RestrictedExpression::new_string(server.name.clone()),
            ),
            (
                "enabled".to_string(),
                RestrictedExpression::new_bool(server.enabled),
            ),
            ("tags".to_string(), tags_set),
            (
                "client_id".to_string(),
                RestrictedExpression::new_string(server.client_id.clone()),
            ),
        ]);

        Entity::new(uid, attrs, HashSet::new())
            .map_err(|e| PolicyError::Evaluation(format!("server entity: {e}")))
    }

    // -----------------------------------------------------------------------
    // Resource entity helpers
    // -----------------------------------------------------------------------

    /// Build a Cedar `Entity` and `EntityUid` for the given `PolicyResource`.
    pub(super) fn build_resource_entity(
        resource: &PolicyResource,
    ) -> Result<(EntityUid, Entity), PolicyError> {
        match resource {
            PolicyResource::Credential { credential: cred } => {
                let type_name: EntityTypeName = entities::CREDENTIAL
                    .parse()
                    .expect("valid entity type name");
                let eid = EntityId::new(cred.id.0.to_string());
                let uid = EntityUid::from_type_name_and_id(type_name, eid);

                let scopes_set = RestrictedExpression::new_set(
                    cred.scopes
                        .iter()
                        .map(|s| RestrictedExpression::new_string(s.clone())),
                );

                let owner_ref = if let Some(ref user_id) = cred.created_by_user {
                    RestrictedExpression::new_entity_uid(Self::user_uid_from_id(user_id))
                } else {
                    let sentinel_id = UserId(uuid::Uuid::nil());
                    RestrictedExpression::new_entity_uid(Self::user_uid_from_id(&sentinel_id))
                };
                let tags_set = RestrictedExpression::new_set(
                    cred.tags
                        .iter()
                        .map(|t| RestrictedExpression::new_string(t.clone())),
                );

                let attrs: HashMap<String, RestrictedExpression> = HashMap::from([
                    (
                        "name".to_string(),
                        RestrictedExpression::new_string(cred.name.clone()),
                    ),
                    (
                        "service".to_string(),
                        RestrictedExpression::new_string(cred.service.clone()),
                    ),
                    ("scopes".to_string(), scopes_set),
                    ("owner".to_string(), owner_ref),
                    ("tags".to_string(), tags_set),
                ]);

                let entity = Entity::new(uid.clone(), attrs, HashSet::new())
                    .map_err(|e| PolicyError::Evaluation(format!("credential entity: {e}")))?;
                Ok((uid, entity))
            }
            PolicyResource::System => {
                let type_name: EntityTypeName =
                    entities::SYSTEM.parse().expect("valid entity type name");
                let eid = EntityId::new("system");
                let uid = EntityUid::from_type_name_and_id(type_name, eid);
                let entity = Entity::new_no_attrs(uid.clone(), HashSet::new());
                Ok((uid, entity))
            }
            PolicyResource::PolicyAdmin => {
                let type_name: EntityTypeName = entities::POLICY_RESOURCE
                    .parse()
                    .expect("valid entity type name");
                let eid = EntityId::new("policies");
                let uid = EntityUid::from_type_name_and_id(type_name, eid);
                let entity = Entity::new_no_attrs(uid.clone(), HashSet::new());
                Ok((uid, entity))
            }
            PolicyResource::McpServer {
                id,
                name,
                enabled,
                tags,
            } => {
                let type_name: EntityTypeName = entities::MCP_SERVER
                    .parse()
                    .expect("valid entity type name");
                let eid = EntityId::new(id.clone());
                let uid = EntityUid::from_type_name_and_id(type_name, eid);

                let tags_set = RestrictedExpression::new_set(
                    tags.iter()
                        .map(|t| RestrictedExpression::new_string(t.clone())),
                );

                let attrs: HashMap<String, RestrictedExpression> = HashMap::from([
                    (
                        "name".to_string(),
                        RestrictedExpression::new_string(name.clone()),
                    ),
                    (
                        "enabled".to_string(),
                        RestrictedExpression::new_bool(*enabled),
                    ),
                    ("tags".to_string(), tags_set),
                ]);

                let entity = Entity::new(uid.clone(), attrs, HashSet::new())
                    .map_err(|e| PolicyError::Evaluation(format!("mcp server entity: {e}")))?;
                Ok((uid, entity))
            }
            PolicyResource::WorkspaceResource { workspace } => {
                let type_name: EntityTypeName = entities::WORKSPACE_RESOURCE
                    .parse()
                    .expect("valid entity type name");
                let eid = EntityId::new(workspace.id.0.to_string());
                let uid = EntityUid::from_type_name_and_id(type_name, eid);

                let mut attrs: HashMap<String, RestrictedExpression> = HashMap::from([
                    (
                        "name".to_string(),
                        RestrictedExpression::new_string(workspace.name.clone()),
                    ),
                    (
                        "enabled".to_string(),
                        RestrictedExpression::new_bool(workspace.enabled),
                    ),
                ]);

                if let Some(ref owner_id) = workspace.owner_id {
                    attrs.insert(
                        "owner".to_string(),
                        RestrictedExpression::new_entity_uid(Self::user_uid_from_id(owner_id)),
                    );
                }

                let entity = Entity::new(uid.clone(), attrs, HashSet::new()).map_err(|e| {
                    PolicyError::Evaluation(format!("workspace resource entity: {e}"))
                })?;
                Ok((uid, entity))
            }
        }
    }

    /// Build the Cedar action `EntityUid` from an action name.
    pub(super) fn action_uid(action: &str) -> EntityUid {
        let type_name: EntityTypeName = entities::ACTION.parse().expect("valid entity type name");
        let eid = EntityId::new(action);
        EntityUid::from_type_name_and_id(type_name, eid)
    }

    /// Build the Cedar `Context` from a `PolicyContext`.
    pub(super) fn build_context(action: &str, ctx: &PolicyContext) -> Result<Context, PolicyError> {
        let timestamp_expr = RestrictedExpression::new_string(
            chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        );

        match action {
            actions::ACCESS => {
                let scopes_expr = RestrictedExpression::new_set(
                    ctx.requested_scopes
                        .iter()
                        .map(|s| RestrictedExpression::new_string(s.clone())),
                );
                Context::from_pairs(vec![
                    ("requested_scopes".to_string(), scopes_expr),
                    ("timestamp".to_string(), timestamp_expr),
                ])
                .map_err(|e| PolicyError::Evaluation(format!("context: {e}")))
            }
            actions::MCP_TOOL_CALL => {
                let tool_name_expr =
                    RestrictedExpression::new_string(ctx.tool_name.clone().unwrap_or_default());
                let credential_name_expr = RestrictedExpression::new_string(
                    ctx.credential_name.clone().unwrap_or_default(),
                );
                let justification_expr =
                    RestrictedExpression::new_string(ctx.justification.clone().unwrap_or_default());
                Context::from_pairs(vec![
                    ("tool_name".to_string(), tool_name_expr),
                    ("credential_name".to_string(), credential_name_expr),
                    ("justification".to_string(), justification_expr),
                    ("timestamp".to_string(), timestamp_expr),
                ])
                .map_err(|e| PolicyError::Evaluation(format!("context: {e}")))
            }
            actions::MCP_LIST_TOOLS => {
                Context::from_pairs(vec![("timestamp".to_string(), timestamp_expr)])
                    .map_err(|e| PolicyError::Evaluation(format!("context: {e}")))
            }
            actions::VEND_CREDENTIAL => {
                let scopes_expr = RestrictedExpression::new_set(
                    ctx.requested_scopes
                        .iter()
                        .map(|s| RestrictedExpression::new_string(s.clone())),
                );
                let target_url_expr =
                    RestrictedExpression::new_string(ctx.target_url.clone().unwrap_or_default());
                let justification_expr =
                    RestrictedExpression::new_string(ctx.justification.clone().unwrap_or_default());
                Context::from_pairs(vec![
                    ("requested_scopes".to_string(), scopes_expr),
                    ("target_url".to_string(), target_url_expr),
                    ("justification".to_string(), justification_expr),
                    ("timestamp".to_string(), timestamp_expr),
                ])
                .map_err(|e| PolicyError::Evaluation(format!("context: {e}")))
            }
            actions::MANAGE_TAGS => {
                let tag_value_expr =
                    RestrictedExpression::new_string(ctx.tag_value.clone().unwrap_or_default());
                Context::from_pairs(vec![
                    ("tag_value".to_string(), tag_value_expr),
                    ("timestamp".to_string(), timestamp_expr),
                ])
                .map_err(|e| PolicyError::Evaluation(format!("context: {e}")))
            }
            _ => Context::from_pairs(vec![("timestamp".to_string(), timestamp_expr)])
                .map_err(|e| PolicyError::Evaluation(format!("context: {e}"))),
        }
    }
}

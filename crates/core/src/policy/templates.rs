use super::{actions, entities};

/// Build a Cedar grant policy for credential access.
pub fn credential_grant_policy(workspace_id: &str, action: &str, credential_id: &str) -> String {
    format!(
        "permit(\n  principal == {}::\"{}\",\n  action == {}::\"{}\",\n  resource == {}::\"{}\"\n);",
        entities::WORKSPACE, workspace_id,
        entities::ACTION, action,
        entities::CREDENTIAL, credential_id,
    )
}

/// Build a Cedar deny (forbid) policy for credential access.
pub fn credential_deny_policy(workspace_id: &str, action: &str, credential_id: &str) -> String {
    format!(
        "forbid(\n  principal == {}::\"{}\",\n  action == {}::\"{}\",\n  resource == {}::\"{}\"\n);",
        entities::WORKSPACE, workspace_id,
        entities::ACTION, action,
        entities::CREDENTIAL, credential_id,
    )
}

/// Build a Cedar grant policy for MCP server access.
pub fn mcp_grant_policy(workspace_id: &str, action: &str, mcp_server_id: &str) -> String {
    format!(
        "permit(\n  principal == {}::\"{}\",\n  action == {}::\"{}\",\n  resource == {}::\"{}\"\n);",
        entities::WORKSPACE, workspace_id,
        entities::ACTION, action,
        entities::MCP_SERVER, mcp_server_id,
    )
}

/// Build a Cedar deny (forbid) policy for MCP server access.
pub fn mcp_deny_policy(workspace_id: &str, action: &str, mcp_server_id: &str) -> String {
    format!(
        "forbid(\n  principal == {}::\"{}\",\n  action == {}::\"{}\",\n  resource == {}::\"{}\"\n);",
        entities::WORKSPACE, workspace_id,
        entities::ACTION, action,
        entities::MCP_SERVER, mcp_server_id,
    )
}

/// Build a Cedar grant policy for a specific MCP tool.
pub fn mcp_tool_grant_policy(workspace_id: &str, tool_name: &str, mcp_server_id: &str) -> String {
    format!(
        "permit(\n  principal == {}::\"{}\",\n  action == {}::\"{}\",\n  resource == {}::\"{}\"\n) when {{\n  context.tool_name == \"{}\"\n}};",
        entities::WORKSPACE, workspace_id,
        entities::ACTION, actions::MCP_TOOL_CALL,
        entities::MCP_SERVER, mcp_server_id,
        tool_name,
    )
}

/// Build a Cedar deny (forbid) policy for a specific MCP tool.
pub fn mcp_tool_deny_policy(workspace_id: &str, tool_name: &str, mcp_server_id: &str) -> String {
    format!(
        "forbid(\n  principal == {}::\"{}\",\n  action == {}::\"{}\",\n  resource == {}::\"{}\"\n) when {{\n  context.tool_name == \"{}\"\n}};",
        entities::WORKSPACE, workspace_id,
        entities::ACTION, actions::MCP_TOOL_CALL,
        entities::MCP_SERVER, mcp_server_id,
        tool_name,
    )
}

/// Map legacy permission names to Cedar action names.
pub fn permission_to_actions(permission: &str) -> Vec<&'static str> {
    match permission {
        "read" => vec![actions::LIST],
        "write" => vec![actions::UPDATE],
        "delete" => vec![actions::DELETE],
        "delegated_use" => vec![actions::VEND_CREDENTIAL],
        "access" => vec![actions::ACCESS],
        "vend_credential" => vec![actions::VEND_CREDENTIAL],
        "list" => vec![actions::LIST],
        "update" => vec![actions::UPDATE],
        _ => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_grant_policy_format() {
        let policy = credential_grant_policy("workspace-1", actions::ACCESS, "cred-1");
        assert!(policy.contains("AgentCordon::Workspace::\"workspace-1\""));
        assert!(policy.contains("AgentCordon::Action::\"access\""));
        assert!(policy.contains("AgentCordon::Credential::\"cred-1\""));
        assert!(policy.starts_with("permit("));
        assert!(policy.ends_with(");"));
    }

    #[test]
    fn credential_deny_policy_format() {
        let policy = credential_deny_policy("workspace-1", actions::ACCESS, "cred-1");
        assert!(policy.contains("AgentCordon::Workspace::\"workspace-1\""));
        assert!(policy.contains("AgentCordon::Action::\"access\""));
        assert!(policy.contains("AgentCordon::Credential::\"cred-1\""));
        assert!(policy.starts_with("forbid("));
        assert!(policy.ends_with(");"));
    }

    #[test]
    fn mcp_grant_policy_format() {
        let policy = mcp_grant_policy(
            "workspace-1",
            actions::MCP_TOOL_CALL,
            "a1b2c3d4-0000-0000-0000-000000000001",
        );
        assert!(policy.contains("AgentCordon::Workspace::\"workspace-1\""));
        assert!(policy.contains("AgentCordon::Action::\"mcp_tool_call\""));
        assert!(policy.contains("AgentCordon::McpServer::\"a1b2c3d4-0000-0000-0000-000000000001\""));
    }

    #[test]
    fn mcp_deny_policy_format() {
        let policy = mcp_deny_policy(
            "workspace-1",
            actions::MCP_TOOL_CALL,
            "a1b2c3d4-0000-0000-0000-000000000002",
        );
        assert!(policy.starts_with("forbid("));
        assert!(policy.contains("AgentCordon::Workspace::\"workspace-1\""));
        assert!(policy.contains("AgentCordon::Action::\"mcp_tool_call\""));
        assert!(policy.contains("AgentCordon::McpServer::\"a1b2c3d4-0000-0000-0000-000000000002\""));
        assert!(policy.ends_with(");"));
    }

    #[test]
    fn mcp_tool_grant_policy_format() {
        let policy = mcp_tool_grant_policy(
            "workspace-1",
            "list_users",
            "a1b2c3d4-0000-0000-0000-000000000003",
        );
        assert!(policy.starts_with("permit("));
        assert!(policy.contains("AgentCordon::Action::\"mcp_tool_call\""));
        assert!(policy.contains("AgentCordon::McpServer::\"a1b2c3d4-0000-0000-0000-000000000003\""));
        assert!(policy.contains("context.tool_name == \"list_users\""));
        assert!(policy.ends_with("};"));
    }

    #[test]
    fn mcp_tool_deny_policy_format() {
        let policy = mcp_tool_deny_policy(
            "workspace-1",
            "list_users",
            "a1b2c3d4-0000-0000-0000-000000000004",
        );
        assert!(policy.starts_with("forbid("));
        assert!(policy.contains("AgentCordon::Action::\"mcp_tool_call\""));
        assert!(policy.contains("context.tool_name == \"list_users\""));
        assert!(policy.ends_with("};"));
    }

    #[test]
    fn permission_mapping_delegated_use() {
        let actions = permission_to_actions("delegated_use");
        assert_eq!(actions, vec!["vend_credential"]);
    }

    #[test]
    fn permission_mapping_read() {
        let actions = permission_to_actions("read");
        assert_eq!(actions, vec!["list"]);
    }

    #[test]
    fn permission_mapping_unknown() {
        let actions = permission_to_actions("unknown_perm");
        assert!(actions.is_empty());
    }
}

// ---------------------------------------------------------------------------
// Tag-Based Credential Access
// ---------------------------------------------------------------------------
// Workspaces can access and proxy credentials when they share at least one tag.
// This enables convention-based access control: tag both the workspace and the
// credential with the same label (e.g., "ci", "deploy", "staging") and
// access is granted automatically — no per-workspace permission grants needed.
//
// Examples:
//   Workspace tags: ["ci", "deploy"]   + Credential tags: ["ci"]       -> PERMIT
//   Workspace tags: ["staging"]        + Credential tags: ["prod"]     -> DENY
//   Workspace tags: ["deploy"]         + Credential tags: ["deploy"]   -> PERMIT
// ---------------------------------------------------------------------------

// Workspaces can decrypt/use credentials that share a tag.
permit(
  principal is AgentCordon::Workspace,
  action == AgentCordon::Action::"access",
  resource is AgentCordon::Credential
) when {
  principal.tags.containsAny(resource.tags)
};

// Workspaces can proxy through credentials that share a tag.
permit(
  principal is AgentCordon::Workspace,
  action == AgentCordon::Action::"vend_credential",
  resource is AgentCordon::Credential
) when {
  principal.tags.containsAny(resource.tags)
};

// Workspaces can list/view credentials that share a tag.
permit(
  principal is AgentCordon::Workspace,
  action == AgentCordon::Action::"list",
  resource is AgentCordon::Credential
) when {
  principal.tags.containsAny(resource.tags)
};

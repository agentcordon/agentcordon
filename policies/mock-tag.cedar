// Agents with the "mock" tag can read credentials tagged "mock".
permit(
  principal is AgentCordon::Agent,
  action == AgentCordon::Action::"access",
  resource is AgentCordon::Credential
) when {
  principal.tags.contains("mock") && resource.tags.contains("mock")
};

// Agents with the "mock" tag can vend_credential credentials tagged "mock".
permit(
  principal is AgentCordon::Agent,
  action == AgentCordon::Action::"vend_credential",
  resource is AgentCordon::Credential
) when {
  principal.tags.contains("mock") && resource.tags.contains("mock")
};

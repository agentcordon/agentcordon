# E2E DAG test nodes
#
# Each module exposes a get_nodes() function returning a list of DagNode instances.
# Import all node modules here so the runner can collect them.

# --- Setup / prerequisites ---
from tests.e2e.nodes.setup import get_nodes as _setup_nodes

# --- Broker lifecycle ---
from tests.e2e.nodes.broker import get_nodes as _broker_nodes

# --- Device flow (v0.3.0 RFC 8628, replaces oauth_flow) ---
from tests.e2e.nodes.device_flow import get_nodes as _device_flow_nodes

# --- Windows installer assets ---
from tests.e2e.nodes.windows import get_nodes as _windows_nodes

# --- Broker proxy ---
from tests.e2e.nodes.broker_proxy import get_nodes as _broker_proxy_nodes

# --- OAuth security ---
from tests.e2e.nodes.oauth_security import get_nodes as _oauth_security_nodes

# --- OAuth audit ---
from tests.e2e.nodes.oauth_audit import get_nodes as _oauth_audit_nodes

# --- Removal verification ---
from tests.e2e.nodes.removal import get_nodes as _removal_nodes

# --- Journey ---
from tests.e2e.nodes.journey import get_nodes as _journey_nodes

# --- Restored feature nodes ---
from tests.e2e.nodes.audit import get_nodes as _audit_nodes
from tests.e2e.nodes.auth import get_nodes as _auth_nodes
from tests.e2e.nodes.controlplane import get_nodes as _controlplane_nodes
from tests.e2e.nodes.credential import get_nodes as _credential_nodes
from tests.e2e.nodes.discovery import get_nodes as _discovery_nodes
from tests.e2e.nodes.grant import get_nodes as _grant_nodes
from tests.e2e.nodes.mcp import get_nodes as _mcp_nodes
from tests.e2e.nodes.negative import get_nodes as _negative_nodes
from tests.e2e.nodes.oauth_proxy import get_nodes as _oauth_proxy_nodes
from tests.e2e.nodes.permission import get_nodes as _permission_nodes
from tests.e2e.nodes.policy import get_nodes as _policy_nodes
from tests.e2e.nodes.proxy import get_nodes as _proxy_nodes
from tests.e2e.nodes.security import get_nodes as _security_nodes
from tests.e2e.nodes.settings import get_nodes as _settings_nodes
from tests.e2e.nodes.ui import get_nodes as _ui_nodes
from tests.e2e.nodes.user import get_nodes as _user_nodes
from tests.e2e.nodes.vault import get_nodes as _vault_nodes

# --- New endpoint coverage ---
from tests.e2e.nodes.sse import get_nodes as _sse_nodes
# --- Scenario-based tests ---
from tests.e2e.nodes.security_scenarios import get_nodes as _security_scenarios_nodes
from tests.e2e.nodes.oauth_edge_cases import get_nodes as _oauth_edge_cases_nodes
from tests.e2e.nodes.tenant_isolation import get_nodes as _tenant_isolation_nodes
from tests.e2e.nodes.error_recovery import get_nodes as _error_recovery_nodes
from tests.e2e.nodes.policy_scenarios import get_nodes as _policy_scenarios_nodes
from tests.e2e.nodes.credential_scenarios import get_nodes as _credential_scenarios_nodes
from tests.e2e.nodes.proxy_scenarios import get_nodes as _proxy_scenarios_nodes
from tests.e2e.nodes.auth_scenarios import get_nodes as _auth_scenarios_nodes


def all_nodes():
    """Return all registered DAG nodes from every module."""
    return (
        _setup_nodes()
        + _broker_nodes()
        + _device_flow_nodes()
        + _windows_nodes()
        + _broker_proxy_nodes()
        + _oauth_security_nodes()
        + _oauth_audit_nodes()
        + _removal_nodes()
        + _journey_nodes()
        + _audit_nodes()
        + _auth_nodes()
        + _controlplane_nodes()
        + _credential_nodes()
        + _discovery_nodes()
        + _grant_nodes()
        + _mcp_nodes()
        + _negative_nodes()
        + _oauth_proxy_nodes()
        + _permission_nodes()
        + _policy_nodes()
        + _proxy_nodes()
        + _security_nodes()
        + _settings_nodes()
        + _ui_nodes()
        + _user_nodes()
        + _vault_nodes()
        + _sse_nodes()
        + _security_scenarios_nodes()
        + _oauth_edge_cases_nodes()
        + _tenant_isolation_nodes()
        + _error_recovery_nodes()
        + _policy_scenarios_nodes()
        + _credential_scenarios_nodes()
        + _proxy_scenarios_nodes()
        + _auth_scenarios_nodes()
    )

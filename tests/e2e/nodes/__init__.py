# E2E DAG test nodes
#
# Each module exposes a get_nodes() function returning a list of DagNode instances.
# Import all node modules here so the runner can collect them.

from tests.e2e.nodes.broker import get_nodes as _broker_nodes
from tests.e2e.nodes.oauth_flow import get_nodes as _oauth_nodes
from tests.e2e.nodes.broker_proxy import get_nodes as _proxy_nodes
from tests.e2e.nodes.oauth_security import get_nodes as _security_nodes
from tests.e2e.nodes.oauth_audit import get_nodes as _audit_nodes
from tests.e2e.nodes.removal import get_nodes as _removal_nodes
from tests.e2e.nodes.journey import get_nodes as _journey_nodes


def all_nodes():
    """Return all registered DAG nodes from every module."""
    return (
        _broker_nodes()
        + _oauth_nodes()
        + _proxy_nodes()
        + _security_nodes()
        + _audit_nodes()
        + _removal_nodes()
        + _journey_nodes()
    )

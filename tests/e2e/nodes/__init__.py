# E2E DAG test nodes
#
# Each module exposes a get_nodes() function returning a list of DagNode instances.
# Import all node modules here so the runner can collect them.

from tests.e2e.nodes.broker import get_nodes as _broker_nodes
from tests.e2e.nodes.oauth_flow import get_nodes as _oauth_nodes
from tests.e2e.nodes.broker_proxy import get_nodes as _proxy_nodes


def all_nodes():
    """Return all registered DAG nodes from every module."""
    return _broker_nodes() + _oauth_nodes() + _proxy_nodes()

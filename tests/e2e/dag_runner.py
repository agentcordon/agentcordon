"""
DAG test runner for AgentCordon E2E tests.

Each test node is a function that:
  - Takes a shared context dict (ctx)
  - Performs its test logic
  - Returns the updated ctx with any produced values
  - Raises on failure

Nodes declare dependencies via `depends_on` and produced context keys via `produces`.
The runner topologically sorts nodes and runs them in dependency order.
"""

import time
import traceback
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set


@dataclass
class DagNode:
    """A single test node in the DAG."""
    name: str
    fn: Callable[[dict], dict]
    depends_on: List[str] = field(default_factory=list)
    produces: List[str] = field(default_factory=list)
    consumes: List[str] = field(default_factory=list)
    critical: bool = False
    timeout: float = 30.0  # seconds

    def __post_init__(self):
        if self.depends_on is None:
            self.depends_on = []
        if self.produces is None:
            self.produces = []
        if self.consumes is None:
            self.consumes = []


@dataclass
class NodeResult:
    """Result of running a single node."""
    name: str
    status: str  # "passed", "failed", "skipped"
    duration: float = 0.0
    error: Optional[str] = None


class DagRunner:
    """Topologically sorts and runs DAG test nodes."""

    def __init__(self):
        self.nodes: Dict[str, DagNode] = {}
        self.results: List[NodeResult] = []

    def add_node(self, node: DagNode):
        self.nodes[node.name] = node

    def _topo_sort(self) -> List[str]:
        """Topological sort via Kahn's algorithm."""
        in_degree: Dict[str, int] = defaultdict(int)
        for name in self.nodes:
            in_degree.setdefault(name, 0)
        for node in self.nodes.values():
            for dep in node.depends_on:
                if dep in self.nodes:
                    in_degree[node.name] += 1

        queue = [n for n in self.nodes if in_degree[n] == 0]
        order = []
        while queue:
            queue.sort()  # deterministic ordering
            current = queue.pop(0)
            order.append(current)
            for node in self.nodes.values():
                if current in node.depends_on:
                    in_degree[node.name] -= 1
                    if in_degree[node.name] == 0:
                        queue.append(node.name)

        if len(order) != len(self.nodes):
            missing = set(self.nodes.keys()) - set(order)
            raise ValueError(f"Cycle detected in DAG involving: {missing}")
        return order

    def run(self, ctx: Optional[dict] = None) -> List[NodeResult]:
        """Run all nodes in topological order."""
        if ctx is None:
            ctx = {}

        order = self._topo_sort()
        failed_nodes: Set[str] = set()
        skipped_nodes: Set[str] = set()

        for name in order:
            node = self.nodes[name]

            # Skip if any dependency failed or was skipped
            skip_reason = None
            for dep in node.depends_on:
                if dep in failed_nodes:
                    skip_reason = f"dependency '{dep}' failed"
                    break
                if dep in skipped_nodes:
                    skip_reason = f"dependency '{dep}' was skipped"
                    break
                if dep not in self.nodes:
                    skip_reason = f"dependency '{dep}' not registered"
                    break

            if skip_reason:
                result = NodeResult(name=name, status="skipped", error=skip_reason)
                self.results.append(result)
                skipped_nodes.add(name)
                print(f"  SKIP  {name} ({skip_reason})")
                continue

            # Check consumed context keys are present
            missing_keys = [k for k in node.consumes if k not in ctx]
            if missing_keys:
                result = NodeResult(
                    name=name, status="skipped",
                    error=f"missing context keys: {missing_keys}"
                )
                self.results.append(result)
                skipped_nodes.add(name)
                print(f"  SKIP  {name} (missing context: {missing_keys})")
                continue

            # Run the node
            start = time.time()
            try:
                ctx = node.fn(ctx)
                duration = time.time() - start
                result = NodeResult(name=name, status="passed", duration=duration)
                self.results.append(result)
                print(f"  PASS  {name} ({duration:.2f}s)")
            except Exception as e:
                duration = time.time() - start
                tb = traceback.format_exc()
                result = NodeResult(
                    name=name, status="failed",
                    duration=duration, error=str(e)
                )
                self.results.append(result)
                failed_nodes.add(name)
                print(f"  FAIL  {name} ({duration:.2f}s)")
                print(f"        {e}")
                if node.critical:
                    print(f"        CRITICAL node failed — downstream nodes will be skipped")

        return self.results

    def summary(self) -> str:
        """Print a summary of all results."""
        passed = sum(1 for r in self.results if r.status == "passed")
        failed = sum(1 for r in self.results if r.status == "failed")
        skipped = sum(1 for r in self.results if r.status == "skipped")
        total = len(self.results)
        total_time = sum(r.duration for r in self.results)

        lines = [
            f"\n{'=' * 60}",
            f"E2E Results: {passed} passed, {failed} failed, {skipped} skipped ({total} total)",
            f"Total time: {total_time:.2f}s",
            f"{'=' * 60}",
        ]

        if failed > 0:
            lines.append("\nFailed nodes:")
            for r in self.results:
                if r.status == "failed":
                    lines.append(f"  - {r.name}: {r.error}")

        return "\n".join(lines)

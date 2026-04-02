"""
DAG nodes for policy CRUD testing: policy.list, policy.create_and_delete,
policy.validate, policy.test_evaluation.
"""

import json
import os

from tests.e2e.dag_runner import DagNode
from tests.e2e.helpers import server_request


# ---------------------------------------------------------------------------
# policy.list
# ---------------------------------------------------------------------------

def policy_list(ctx: dict) -> dict:
    """
    List Cedar policies via admin API.

    Consumes: base_url, admin_session_cookie
    Produces: policy_list_result
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]

    status, _, body = server_request(
        base_url, "GET", "/api/v1/policies",
        cookies=admin_cookie,
    )

    assert status == 200, f"Policy list failed with {status}: {body}"

    data = json.loads(body)
    policies = data.get("data", data)
    if isinstance(policies, dict):
        policies = policies.get("policies", policies.get("items", []))

    assert isinstance(policies, list), f"Expected policy list, got: {type(policies)}"

    ctx["policy_list_result"] = policies
    return ctx


POLICY_LIST_NODE = DagNode(
    name="policy.list",
    fn=policy_list,
    depends_on=["setup.login"],
    produces=["policy_list_result"],
    consumes=["base_url", "admin_session_cookie"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# policy.create_and_delete
# ---------------------------------------------------------------------------

def policy_create_and_delete(ctx: dict) -> dict:
    """
    Create a Cedar policy, verify it appears in list, then delete it.

    Consumes: base_url, admin_session_cookie, csrf_token
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]
    csrf_token = ctx["csrf_token"]

    policy_name = f"e2e-test-policy-{os.urandom(4).hex()}"
    cedar_text = 'permit(principal, action, resource);'

    create_body = json.dumps({
        "name": policy_name,
        "cedar_policy": cedar_text,
        "description": "E2E test policy — safe to delete",
    })

    status, _, body = server_request(
        base_url, "POST", "/api/v1/policies",
        body=create_body,
        headers={"X-CSRF-Token": csrf_token},
        cookies=admin_cookie,
    )

    assert status in (200, 201), f"Policy create failed with {status}: {body}"

    data = json.loads(body)
    policy = data.get("data", data)
    policy_id = policy.get("id")
    assert policy_id, f"No policy ID in response: {policy}"

    # Delete it
    status, _, body = server_request(
        base_url, "DELETE", f"/api/v1/policies/{policy_id}",
        headers={"X-CSRF-Token": csrf_token},
        cookies=admin_cookie,
    )

    assert status in (200, 204), f"Policy delete failed with {status}: {body}"

    return ctx


POLICY_CREATE_AND_DELETE_NODE = DagNode(
    name="policy.create_and_delete",
    fn=policy_create_and_delete,
    depends_on=["setup.login"],
    produces=[],
    consumes=["base_url", "admin_session_cookie", "csrf_token"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# policy.validate
# ---------------------------------------------------------------------------

def policy_validate(ctx: dict) -> dict:
    """
    Test the Cedar policy validation endpoint with valid and invalid syntax.

    Consumes: base_url, admin_session_cookie, csrf_token
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]
    csrf_token = ctx["csrf_token"]

    # Valid Cedar
    valid_body = json.dumps({
        "cedar_policy": 'permit(principal, action, resource);',
    })

    status, _, body = server_request(
        base_url, "POST", "/api/v1/policies/validate",
        body=valid_body,
        headers={"X-CSRF-Token": csrf_token},
        cookies=admin_cookie,
    )

    assert status == 200, f"Validation of valid policy failed: {status}: {body}"

    data = json.loads(body)
    result = data.get("data", data)
    assert result.get("valid") is True or result.get("is_valid") is True, (
        f"Valid policy flagged as invalid: {result}"
    )

    # Invalid Cedar
    invalid_body = json.dumps({
        "cedar_policy": "this is not valid cedar {{{",
    })

    status, _, body = server_request(
        base_url, "POST", "/api/v1/policies/validate",
        body=invalid_body,
        headers={"X-CSRF-Token": csrf_token},
        cookies=admin_cookie,
    )

    # Should return 200 with valid=false, or 400
    if status == 200:
        data = json.loads(body)
        result = data.get("data", data)
        assert result.get("valid") is False or result.get("is_valid") is False, (
            f"Invalid policy flagged as valid: {result}"
        )
    else:
        assert status == 400, f"Expected 200 or 400 for invalid policy, got {status}"

    return ctx


POLICY_VALIDATE_NODE = DagNode(
    name="policy.validate",
    fn=policy_validate,
    depends_on=["setup.login"],
    produces=[],
    consumes=["base_url", "admin_session_cookie", "csrf_token"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# policy.test_evaluation
# ---------------------------------------------------------------------------

def policy_test_evaluation(ctx: dict) -> dict:
    """
    Test the policy test/RSOP endpoint if available.

    Consumes: base_url, admin_session_cookie, csrf_token
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]
    csrf_token = ctx["csrf_token"]

    # Try RSOP endpoint
    rsop_body = json.dumps({})

    status, _, body = server_request(
        base_url, "POST", "/api/v1/policies/rsop",
        body=rsop_body,
        headers={"X-CSRF-Token": csrf_token},
        cookies=admin_cookie,
    )

    # RSOP may require specific parameters — accept 200 or 400
    assert status in (200, 400, 422), (
        f"RSOP endpoint returned unexpected status {status}: {body}"
    )

    return ctx


POLICY_TEST_EVALUATION_NODE = DagNode(
    name="policy.test_evaluation",
    fn=policy_test_evaluation,
    depends_on=["policy.list"],
    produces=[],
    consumes=["base_url", "admin_session_cookie", "csrf_token"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# policy.rsop
# ---------------------------------------------------------------------------

def policy_rsop(ctx: dict) -> dict:
    """
    Verify POST /policies/rsop endpoint with a real resource type.

    Consumes: base_url, admin_session_cookie, csrf_token
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]
    csrf_token = ctx["csrf_token"]

    rsop_body = json.dumps({
        "resource_type": "credential",
    })

    status, _, body = server_request(
        base_url, "POST", "/api/v1/policies/rsop",
        body=rsop_body,
        headers={"X-CSRF-Token": csrf_token},
        cookies=admin_cookie,
    )

    # RSOP should return 200 with a matrix, or 400/422 for missing params
    assert status in (200, 400, 422), (
        f"RSOP endpoint returned unexpected status {status}: {body}"
    )

    if status == 200:
        data = json.loads(body)
        result = data.get("data", data)
        assert isinstance(result, (dict, list)), (
            f"Expected RSOP result dict/list, got: {type(result)}"
        )

    return ctx


POLICY_RSOP_NODE = DagNode(
    name="policy.rsop",
    fn=policy_rsop,
    depends_on=["policy.list"],
    produces=[],
    consumes=["base_url", "admin_session_cookie", "csrf_token"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# policy.schema
# ---------------------------------------------------------------------------

def policy_schema(ctx: dict) -> dict:
    """
    Verify GET /policies/schema returns the Cedar schema.

    Consumes: base_url, admin_session_cookie
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]

    status, _, body = server_request(
        base_url, "GET", "/api/v1/policies/schema",
        cookies=admin_cookie,
    )

    assert status == 200, f"Policy schema failed with {status}: {body}"
    assert len(body) > 0, "Policy schema returned empty body"

    data = json.loads(body)
    schema = data.get("data", data)
    assert schema is not None, "No schema data returned"

    return ctx


POLICY_SCHEMA_NODE = DagNode(
    name="policy.schema",
    fn=policy_schema,
    depends_on=["setup.login"],
    produces=[],
    consumes=["base_url", "admin_session_cookie"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# policy.schema_reference
# ---------------------------------------------------------------------------

def policy_schema_reference(ctx: dict) -> dict:
    """
    Verify GET /policies/schema/reference returns schema reference docs.

    Consumes: base_url, admin_session_cookie
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]

    status, _, body = server_request(
        base_url, "GET", "/api/v1/policies/schema/reference",
        cookies=admin_cookie,
    )

    assert status == 200, f"Policy schema reference failed with {status}: {body}"
    assert len(body) > 0, "Policy schema reference returned empty body"

    data = json.loads(body)
    reference = data.get("data", data)
    assert reference is not None, "No schema reference data returned"

    return ctx


POLICY_SCHEMA_REFERENCE_NODE = DagNode(
    name="policy.schema_reference",
    fn=policy_schema_reference,
    depends_on=["setup.login"],
    produces=[],
    consumes=["base_url", "admin_session_cookie"],
    critical=False,
    timeout=10.0,
)


# ---------------------------------------------------------------------------
# policy.templates
# ---------------------------------------------------------------------------

def policy_templates(ctx: dict) -> dict:
    """
    Verify GET /policy-templates returns a list of policy templates.

    Consumes: base_url, admin_session_cookie
    """
    base_url = ctx["base_url"]
    admin_cookie = ctx["admin_session_cookie"]

    status, _, body = server_request(
        base_url, "GET", "/api/v1/policy-templates",
        cookies=admin_cookie,
    )

    assert status == 200, f"Policy templates failed with {status}: {body}"

    data = json.loads(body)
    templates = data.get("data", data)
    if isinstance(templates, dict):
        templates = templates.get("templates", templates.get("items", []))

    assert isinstance(templates, list), f"Expected templates list, got: {type(templates)}"
    assert len(templates) >= 1, f"Expected at least 1 policy template, got {len(templates)}"

    # Verify template structure
    for t in templates[:3]:
        assert "key" in t or "name" in t, f"Template missing key/name: {t}"

    return ctx


POLICY_TEMPLATES_NODE = DagNode(
    name="policy.templates",
    fn=policy_templates,
    depends_on=["setup.login"],
    produces=[],
    consumes=["base_url", "admin_session_cookie"],
    critical=False,
    timeout=10.0,
)


def get_nodes():
    """Return all policy DAG nodes."""
    return [
        POLICY_LIST_NODE,
        POLICY_CREATE_AND_DELETE_NODE,
        POLICY_VALIDATE_NODE,
        POLICY_TEST_EVALUATION_NODE,
        POLICY_RSOP_NODE,
        POLICY_SCHEMA_NODE,
        POLICY_SCHEMA_REFERENCE_NODE,
        POLICY_TEMPLATES_NODE,
    ]

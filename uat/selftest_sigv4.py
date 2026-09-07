#!/usr/bin/env python3
"""Self-test for the SigV4 verifier in uat/mock_upstream.py.

Checks the verifier's canonicalisation against the published
`aws-sig-v4-test-suite` "get-vanilla" vector, so a UAT failure can be blamed on
the product rather than on the mock. Run: python3 uat/selftest_sigv4.py
"""

import hashlib
import hmac
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("mu", os.path.join(HERE, "mock_upstream.py"))
mu = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mu)

SECRET = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
AMZ_DATE = "20150830T123600Z"
SCOPE = "20150830/us-east-1/service/aws4_request"
EXPECTED = "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"

signed = ["host", "x-amz-date"]
headers = {"host": "example.amazonaws.com", "x-amz-date": AMZ_DATE}
lines = "".join("%s:%s\n" % (n, mu.canonical_header_value(headers[n])) for n in signed)
canonical_request = "%s\n%s\n%s\n%s\n%s\n%s" % (
    "GET",
    mu.canonical_uri_path("/", True),
    mu.canonical_query_string(""),
    lines,
    ";".join(signed),
    hashlib.sha256(b"").hexdigest(),
)
string_to_sign = "\n".join(
    ["AWS4-HMAC-SHA256", AMZ_DATE, SCOPE, hashlib.sha256(canonical_request.encode()).hexdigest()]
)
key = mu.hmac_sha256(("AWS4" + SECRET).encode(), "20150830")
key = mu.hmac_sha256(key, "us-east-1")
key = mu.hmac_sha256(key, "service")
key = mu.hmac_sha256(key, "aws4_request")
signature = hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()

failures = []
if signature != EXPECTED:
    failures.append("get-vanilla signature %s != %s" % (signature, EXPECTED))

# Non-S3 services double-encode each path segment: ' ' -> %20 -> %2520.
if mu.canonical_uri_path("/sigv4/a%20b", True) != "/sigv4/a%2520b":
    failures.append("double encoding: %s" % mu.canonical_uri_path("/sigv4/a%20b", True))
if mu.canonical_uri_path("/sigv4/a%20b", False) != "/sigv4/a%20b":
    failures.append("single encoding: %s" % mu.canonical_uri_path("/sigv4/a%20b", False))
# Query parameters are encoded once and sorted by key then value.
if mu.canonical_query_string("x=1&a=hello world") != "a=hello%20world&x=1":
    failures.append("query: %s" % mu.canonical_query_string("x=1&a=hello world"))

if failures:
    for f in failures:
        print("FAIL " + f)
    sys.exit(1)
print("mock_upstream SigV4 verifier: all self-tests passed")

import { test, expect } from '@playwright/test';
import { UAT } from './helpers/env';
import { cli } from './helpers/docker';
import { apiFromPage, expectOk, login, shot } from './helpers/ui';
import { writeState } from './helpers/state';
import { readDoc } from './helpers/docs';

/**
 * S14 — An AWS credential signed with SigV4.
 *
 * Documented steps:
 *   docs/credential-encryption.md § "Credential Types / AWS":
 *     "Fields: aws_access_key_id, aws_secret_access_key, optional aws_region,
 *      aws_service. Default transform: aws-sigv4. Auto-default
 *      allowed_url_pattern: https://*.amazonaws.com/*"
 *   docs/cli-reference.md § "Credential Types and Transforms":
 *     `aws` -> "AWS SigV4 ... Authorization and x-amz-date headers".
 *   README.md § "Quick Start / 4. Use credentials" (`agentcordon proxy`).
 *   CHANGELOG [Unreleased] § Fixed: "AWS SigV4 double-encodes paths for
 *     non-S3 services ... any path segment with a space, +, or other reserved
 *     character signed wrong for Lambda, API Gateway, and the rest."
 *
 * The mock upstream verifies the signature the way AWS does: it rebuilds the
 * canonical request from the headers the signer listed in SignedHeaders and
 * recomputes the signature with the fixed secret.
 */
test.describe('S14 AWS SigV4', () => {
  test('an admin stores an AWS credential from the AWS template on /credentials/new, and the docs name the region/service caveat [G16]', async ({
    page,
  }, testInfo) => {
    await login(page);
    await page.goto('/credentials/new');

    // Selecting a template overwrites name, service, URL pattern and tags, so
    // click the card first and fill afterwards.
    await page.click('button.template-card:has-text("AWS")');
    await expect(page.locator('#cred-field-aws_access_key_id')).toBeVisible();
    await page.fill('#cred-field-aws_access_key_id', UAT.awsAccessKeyId);
    await page.fill('#cred-field-aws_secret_access_key', UAT.awsSecretAccessKey);
    await page.fill('#cred-field-aws_region', UAT.awsRegion);
    await page.fill('#cred-field-aws_service', UAT.awsService);

    await page.fill('#cred-name', UAT.awsName);
    await page.fill('#cred-service', 'aws');
    await page.fill('#cred-url-pattern', UAT.awsPattern);
    await shot(page, testInfo, 's14-aws-credential-form');

    const created = page.waitForResponse(
      (r) => r.url().endsWith('/api/v1/credentials') && r.request().method() === 'POST',
      { timeout: 30_000 },
    );
    await page.click('button[type="submit"]:has-text("Store Credential")');
    const response = await created;
    await expectOk(page, response, 'storing the credential');

    await page.waitForURL(/\/credentials\/[0-9a-f-]{36}$/, { timeout: 30_000 });
    const id = page.url().split('/').pop()!;
    writeState({ awsCredentialId: id });

    const detail = await apiFromPage(page, 'GET', `/api/v1/credentials/${id}`);
    expect(detail.status, JSON.stringify(detail.body)).toBe(200);
    expect(detail.body.data.credential_type).toBe('aws');
    expect(detail.body.data.transform_name).toBe('aws-sigv4');
    expect(detail.body.data.allowed_url_pattern).toBe(UAT.awsPattern);
    expect(JSON.stringify(detail.body)).not.toContain(UAT.awsSecretAccessKey);
    await shot(page, testInfo, 's14-aws-credential-detail');

    // G16 — `aws_region` and `aws_service` were documented as plain
    // "optional" while infer_aws_region_service errors out for any host that
    // does not end in .amazonaws.com, so a credential stored without them
    // failed at proxy time against a VPC endpoint, an S3-compatible store or
    // a gateway on a custom domain. Both documents now carry the caveat.
    // Reading the shipped files means this goes red if the caveat is deleted.
    const credDoc = readDoc('docs/credential-encryption.md');
    expect(
      credDoc,
      'docs/credential-encryption.md must say the AWS fields are only optional for *.amazonaws.com',
    ).toContain('only optional for `*.amazonaws.com` targets');
    const cliDoc = readDoc('docs/cli-reference.md');
    expect(cliDoc).toContain('`aws_region` and `aws_service` are optional *only* when');
  });

  test('a proxied GET is signed and the upstream verifies the signature (docs/cli-reference.md § "Credential Types and Transforms")', async () => {
    const r = cli(['proxy', UAT.awsName, 'GET', 'http://upstream:8080/sigv4?x=1']);
    expect(r.code, r.out).toBe(0);
    expect(r.out, r.out).toContain('HTTP 200');
    expect(r.out).toContain('"sigv4_verified":true');
    expect(r.out).toContain(UAT.awsAccessKeyId);
    expect(r.out).toContain(`${UAT.awsRegion}/${UAT.awsService}/aws4_request`);
    // The signed header set must at least cover host and x-amz-date.
    expect(r.out).toContain('"host"');
    expect(r.out).toContain('"x-amz-date"');
    // Non-S3 services must not get x-amz-content-sha256.
    expect(r.out).not.toContain('x-amz-content-sha256');
    expect(r.out, 'the secret key must never reach the caller').not.toContain(
      UAT.awsSecretAccessKey,
    );
  });

  test('a path segment with a reserved character still verifies (double-encoding, CHANGELOG [Unreleased])', async () => {
    const encoded = cli([
      'proxy',
      UAT.awsName,
      'GET',
      'http://upstream:8080/sigv4/a%20b?x=1',
    ]);
    expect(encoded.code, encoded.out).toBe(0);
    expect(encoded.out, encoded.out).toContain('HTTP 200');
    expect(encoded.out).toContain('"sigv4_verified":true');
    // The canonical URI is the segment encoded twice: ' ' -> %20 -> %2520.
    expect(encoded.out).toContain('/sigv4/a%2520b');

    const plus = cli(['proxy', UAT.awsName, 'GET', 'http://upstream:8080/sigv4/a+b?x=1']);
    expect(plus.code, plus.out).toBe(0);
    expect(plus.out, plus.out).toContain('HTTP 200');
    expect(plus.out).toContain('"sigv4_verified":true');
  });

  test('a POST body is covered by the signature', async () => {
    const r = cli([
      'proxy',
      UAT.awsName,
      'POST',
      'http://upstream:8080/sigv4',
      '--body',
      '{"dataset":"users"}',
    ]);
    expect(r.code, r.out).toBe(0);
    expect(r.out, r.out).toContain('HTTP 200');
    expect(r.out).toContain('"sigv4_verified":true');
  });

  test('a target outside allowed_url_pattern is refused (S16: enforcement for the AWS type)', async () => {
    const r = cli(['proxy', UAT.awsName, 'GET', 'http://evil.example/x']);
    expect(r.code, r.out).not.toBe(0);
    expect(r.out).toMatch(/url_pattern_denied|forbidden|403/i);
    expect(r.out).not.toContain(UAT.awsSecretAccessKey);
  });
});

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
 *      allowed_url_pattern: https://**.amazonaws.com/*" — `**` is one or more
 *      DNS labels. The 0.4.0 default was `https://*.amazonaws.com/*`, and a
 *      single `*` is exactly one label, so it covered `sts.amazonaws.com` and
 *      not one regional endpoint (`ssm.us-east-1.amazonaws.com`). This suite
 *      always filled the pattern in by hand, which is why nothing caught it.
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
      'docs/credential-encryption.md must say the AWS fields are only optional for **.amazonaws.com',
    ).toContain('only optional for `**.amazonaws.com` targets');
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

  test('an AWS credential stored with the URL pattern left blank gets the documented default, and the AWS template offers the same (docs/credential-encryption.md § "AWS")', async ({
    page,
  }, testInfo) => {
    await login(page);
    await page.goto('/credentials/new');
    await page.click('button.template-card:has-text("AWS")');
    await expect(page.locator('#cred-field-aws_access_key_id')).toBeVisible();

    // The template pre-fills the fence. It has to be the any-depth form: the
    // one thing every AWS user does first is call a regional endpoint.
    await expect(page.locator('#cred-url-pattern')).toHaveValue('https://**.amazonaws.com/*');

    // Now clear it, so what is stored is the server's own auto-default and
    // not the template's text.
    await page.fill('#cred-url-pattern', '');
    await page.fill('#cred-field-aws_access_key_id', UAT.awsAccessKeyId);
    await page.fill('#cred-field-aws_secret_access_key', UAT.awsSecretAccessKey);
    await page.fill('#cred-field-aws_region', UAT.awsRegion);
    await page.fill('#cred-field-aws_service', UAT.awsService);
    await page.fill('#cred-name', UAT.awsDefaultName);
    await page.fill('#cred-service', 'aws');
    await shot(page, testInfo, 's14-aws-default-fence-form');

    const created = page.waitForResponse(
      (r) => r.url().endsWith('/api/v1/credentials') && r.request().method() === 'POST',
      { timeout: 30_000 },
    );
    await page.click('button[type="submit"]:has-text("Store Credential")');
    await expectOk(page, await created, 'storing the credential');
    await page.waitForURL(/\/credentials\/[0-9a-f-]{36}$/, { timeout: 30_000 });
    const id = page.url().split('/').pop()!;
    writeState({ awsDefaultCredentialId: id });

    const detail = await apiFromPage(page, 'GET', `/api/v1/credentials/${id}`);
    expect(detail.status, JSON.stringify(detail.body)).toBe(200);
    expect(detail.body.data.allowed_url_pattern).toBe('https://**.amazonaws.com/*');
    await shot(page, testInfo, 's14-aws-default-fence-detail');

    // The workspace sees the fence it will be matched against.
    const list = cli(['credentials']);
    expect(list.code, list.out).toBe(0);
    expect(list.out).toContain(UAT.awsDefaultName);
    expect(list.out).toContain('https://**.amazonaws.com/*');
  });

  test('the default fence covers a regional endpoint: --auto picks the credential for ssm.us-east-1 and nothing refuses it as out of pattern', async () => {
    // `ssm.us-east-1.amazonaws.com` is a second alias of the mock upstream on
    // the harness network, so this resolves inside Docker and the connection
    // that follows fails (the mock is plain HTTP on 8080, not TLS on 443).
    // That failure is the expected outcome; what is measured is everything
    // before it: the fence admitted the target and the broker went to call
    // it. Before this release the same command exited 7 ("no credential is
    // fenced for ...") and a direct call exited 5 (`url_pattern_denied`).
    const target = `https://${UAT.awsRegionalHost}/`;

    const auto = cli(['proxy', '--auto', 'GET', target]);
    expect(auto.code, auto.out).not.toBe(7);
    expect(auto.out).not.toContain('no credential is fenced');
    expect(auto.code, 'the fence admitted the target; the upstream did not answer').toBe(6);

    const direct = cli(['proxy', UAT.awsDefaultName, 'GET', target]);
    expect(direct.code, direct.out).not.toBe(5);
    expect(direct.out).not.toContain('url_pattern_denied');
    expect(direct.code, direct.out).toBe(6);
    expect(direct.out).not.toContain(UAT.awsSecretAccessKey);

    // And the apex is still outside: `**` is one or more labels, never none.
    const apex = cli(['proxy', UAT.awsDefaultName, 'GET', 'https://amazonaws.com/']);
    expect(apex.code, apex.out).toBe(5);
    expect(apex.out).toContain('url_pattern_denied');
  });
});

import { test, expect } from '@playwright/test';
import { UAT } from './helpers/env';
import { cli } from './helpers/docker';
import { apiFromPage, login } from './helpers/ui';
import {
  callTool,
  listTools,
  mcpServe,
  resultJson,
  resultText,
  toolNames,
  toolResult,
} from './helpers/mcpserve';

/**
 * S18 — the CLI as a stdio MCP server (`agentcordon mcp-serve`).
 *
 * Documented steps:
 *   docs/cli-reference.md § "agentcordon mcp-serve" — stdio, newline-delimited
 *     JSON-RPC 2.0, the six first-party tools, and `--expose <server>`.
 *   docs/workspace-enrollment.md § "What `init` writes" — `init` registers
 *     this command with each selected runtime (`.mcp.json` for Claude Code).
 *   docs/admin-ui.md § "Enrollment pages" — native tools appear as
 *     `agentcordon_*`.
 *   README.md § "Quick start / 3. Set up a project".
 *
 * Every assertion below is on something the documented interface produces: the
 * `initialize` result, the tool list, and the content of a tool result. The
 * admin API is read only for *evidence* — the audit rows a call left behind —
 * never to drive a step.
 *
 * It runs after S13 because it uses the `uat-none` MCP server S13 installs,
 * and after S2/S3 because it uses that credential and that enrolled workspace.
 */

const S18_ECHO_URL = 'http://upstream:8080/echo';
const OUT_OF_FENCE_URL = 'http://evil.example/x';
const INJECTION_MARKER = 'UAT-INJECTION-4f2b';

/** The six tools the fixed surface must expose, and nothing else. */
const FIXED_TOOLS = [
  'agentcordon_status',
  'agentcordon_credentials',
  'agentcordon_proxy',
  'agentcordon_mcp_servers',
  'agentcordon_mcp_tools',
  'agentcordon_mcp_call',
];

/** `agentcordon --version` prints `agentcordon <version>`. */
function cliVersion(): string {
  const r = cli(['--version']);
  expect(r.code, r.out).toBe(0);
  const m = /(\d+\.\d+\.\d+\S*)/.exec(r.out);
  expect(m, `no version in ${JSON.stringify(r.out)}`).toBeTruthy();
  return m![1];
}

/** Every `credential_vended` row the server has, newest first. */
async function vendRows(page: any): Promise<any[]> {
  const audit = await apiFromPage(page, 'GET', '/api/v1/audit?limit=200');
  expect(audit.status, JSON.stringify(audit.body)).toBe(200);
  return audit.body.data.filter((e: any) => e.event_type === 'credential_vended');
}

test.describe('S18 mcp-serve', () => {
  test('initialize names the product, the CLI version, tools.listChanged and the workspace (docs/cli-reference.md § "agentcordon mcp-serve")', async () => {
    const session = mcpServe([]);
    expect(session.error, session.describe()).toBeNull();
    expect(session.initialize_error, session.describe()).toBeNull();

    const init = session.initialize;
    expect(init, session.describe()).toBeTruthy();
    expect(init.serverInfo?.name, session.describe()).toBe('agentcordon');
    // The MCP client shows this version to the user; it must be the CLI's own,
    // not a hand-maintained constant that drifts from `--version`.
    expect(init.serverInfo?.version, session.describe()).toBe(cliVersion());
    expect(init.capabilities?.tools?.listChanged, session.describe()).toBe(true);

    // `instructions` is the only prose a runtime loads with the server, so it
    // has to say which workspace these tools act as.
    expect(typeof init.instructions, session.describe()).toBe('string');
    expect(init.instructions, session.describe()).toContain(UAT.workspaceName);

    // stdout is the transport. Anything the server prints that is not a
    // JSON-RPC message corrupts the session; logging belongs on stderr.
    expect(session.unparsed_stdout, session.describe()).toEqual([]);
  });

  test('tools/list is exactly the six first-party tools when nothing is exposed (issue #54 amendment: a fixed context cost)', async () => {
    const session = mcpServe([listTools()]);
    expect(session.error, session.describe()).toBeNull();

    const names = toolNames(session.responses[0]);
    // Exactly six: the whole point of the fixed surface is that a workspace
    // with twenty MCP servers costs a session the same as one with one.
    expect(names.slice().sort(), session.describe()).toEqual(FIXED_TOOLS.slice().sort());

    // Each one is callable as it stands: a name, a description and an object
    // schema is what a runtime needs to offer it to the model.
    for (const tool of session.responses[0].result.tools) {
      expect(typeof tool.description, JSON.stringify(tool)).toBe('string');
      expect(tool.description.length, JSON.stringify(tool)).toBeGreaterThan(10);
      expect(tool.inputSchema?.type, JSON.stringify(tool)).toBe('object');
    }
  });

  test('agentcordon_credentials lists the credential the admin created, with its URL fence', async () => {
    const session = mcpServe([callTool('agentcordon_credentials')]);
    expect(session.error, session.describe()).toBeNull();

    const result = toolResult(session.responses[0]);
    expect(result.isError ?? false, session.describe()).toBe(false);

    const text = resultText(session.responses[0]);
    expect(text, session.describe()).toContain(UAT.credentialName);
    // The fence is the field an agent picks a credential by; the CLI's own
    // listing carries an ALLOWED URL column and the MCP surface must not lose
    // it on the way through.
    expect(text, session.describe()).toContain(UAT.credentialPattern);
    expect(text, 'a secret must never reach the model').not.toContain(UAT.credentialSecret);
  });

  test('agentcordon_proxy with no credential named reaches the upstream, redacts the injected value, and leaves a credential_vended row naming the target (docs/system-architecture.md § "A credential vend")', async ({
    page,
  }) => {
    await login(page);
    const before = new Set((await vendRows(page)).map((e: any) => e.id));

    const session = mcpServe([
      callTool('agentcordon_proxy', { method: 'GET', url: S18_ECHO_URL }),
    ]);
    expect(session.error, session.describe()).toBeNull();

    const result = toolResult(session.responses[0]);
    expect(result.isError ?? false, session.describe()).toBe(false);

    // The documented shape: one text block holding JSON {status, headers, body}.
    const proxied = resultJson(session.responses[0]);
    expect(proxied.status, session.describe()).toBe(200);
    expect(proxied.headers, session.describe()).toBeTruthy();

    // The mock upstream echoes the request it received, so `body` is that echo
    // and the injected Authorization header comes back scrubbed.
    const echoed = typeof proxied.body === 'string' ? JSON.parse(proxied.body) : proxied.body;
    expect(echoed.path, session.describe()).toBe('/echo');
    expect(echoed.headers.authorization, session.describe()).toBe('[REDACTED]');
    expect(
      JSON.stringify(session.responses[0]),
      'the raw secret must never reach the model',
    ).not.toContain(UAT.credentialSecret);

    // EVIDENCE ONLY (a raw API read): the call went through the control plane,
    // so the server has a vend row for it that names the URL.
    const after = await vendRows(page);
    const fresh = after.filter((e: any) => !before.has(e.id));
    const row = fresh.find(
      (e: any) => e.metadata && e.metadata.target_url === S18_ECHO_URL,
    );
    expect(row, `new vend rows: ${JSON.stringify(fresh)}`).toBeTruthy();
    expect(row.workspace_name).toBe(UAT.workspaceName);
    expect(row.decision).toBe('permit');
    expect(row.metadata.credential_name).toBe(UAT.credentialName);
  });

  test('agentcordon_proxy refuses a URL no fence covers, and the refusal names the fence (docs/credential-encryption.md § allowed_url_pattern)', async () => {
    const session = mcpServe([
      // Named credential: the refusal must say which pattern fenced it out.
      callTool('agentcordon_proxy', {
        credential: UAT.credentialName,
        method: 'GET',
        url: OUT_OF_FENCE_URL,
      }),
      // No credential named: the refusal must say nothing is fenced for it,
      // rather than picking one at random.
      callTool('agentcordon_proxy', { method: 'GET', url: OUT_OF_FENCE_URL }),
    ]);
    expect(session.error, session.describe()).toBeNull();

    const named = toolResult(session.responses[0]);
    expect(named.isError, session.describe()).toBe(true);
    const namedText = resultText(session.responses[0]);
    expect(namedText, session.describe()).toContain(UAT.credentialPattern);
    expect(namedText, session.describe()).toContain(OUT_OF_FENCE_URL);

    const auto = toolResult(session.responses[1]);
    expect(auto.isError, session.describe()).toBe(true);
    expect(resultText(session.responses[1]), session.describe()).toMatch(
      /no credential is fenced for/i,
    );

    // An error is a tool result the model can read, not a transport failure:
    // the session survives it and the second call still got an answer.
    expect(session.responses).toHaveLength(2);
  });

  test('agentcordon_mcp_tools returns the uat-none server\'s four tools with their input schemas [D11]', async () => {
    const session = mcpServe([callTool('agentcordon_mcp_tools', { server: 'uat-none' })]);
    expect(session.error, session.describe()).toBeNull();

    const result = toolResult(session.responses[0]);
    expect(result.isError ?? false, session.describe()).toBe(false);

    const payload = resultJson(session.responses[0]);
    const tools: any[] = Array.isArray(payload) ? payload : payload.tools;
    expect(Array.isArray(tools), session.describe()).toBe(true);
    expect(tools.map((t) => t.name).sort(), session.describe()).toEqual([
      'echo',
      'echo_raw_auth',
      'team_notice',
      'whoami',
    ]);

    // The schema is what makes `agentcordon_mcp_call` usable without guessing
    // argument names. Both spellings are accepted: the MCP wire name is
    // `inputSchema`, the CLI's own JSON has carried `input_schema`.
    const echo = tools.find((t) => t.name === 'echo');
    const schema = echo.inputSchema ?? echo.input_schema;
    expect(schema, JSON.stringify(echo)).toBeTruthy();
    expect(schema.type).toBe('object');
    expect(Object.keys(schema.properties || {}), JSON.stringify(echo)).toContain('hello');
    expect(typeof echo.description, JSON.stringify(echo)).toBe('string');
    expect(echo.description).toContain('Echo');
  });

  test('agentcordon_mcp_call returns the upstream result unchanged and a correlation id that matches an mcp_tool_called audit row', async ({
    page,
  }) => {
    const session = mcpServe([
      callTool('agentcordon_mcp_call', {
        server: 'uat-none',
        tool: 'echo',
        arguments: { hello: 'world' },
      }),
    ]);
    expect(session.error, session.describe()).toBeNull();

    const result = toolResult(session.responses[0]);
    expect(result.isError ?? false, session.describe()).toBe(false);

    // "Unchanged" is measurable: the mock attaches a prompt injection to every
    // echo result, so its presence proves the content was passed through and
    // not summarised or filtered by the MCP surface.
    const text = resultText(session.responses[0]);
    expect(text, session.describe()).toContain('world');
    expect(text, session.describe()).toContain(INJECTION_MARKER);

    const correlationId = result._meta?.correlation_id;
    expect(correlationId, session.describe()).toBeTruthy();

    // EVIDENCE ONLY (a raw API read): that id is the one the server audited,
    // which is what makes it worth handing to the model at all.
    await login(page);
    const audit = await apiFromPage(page, 'GET', '/api/v1/audit?limit=200');
    expect(audit.status, JSON.stringify(audit.body)).toBe(200);
    const row = audit.body.data.find(
      (e: any) => e.event_type === 'mcp_tool_called' && e.correlation_id === correlationId,
    );
    expect(
      row,
      `no mcp_tool_called row with correlation_id ${correlationId}`,
    ).toBeTruthy();
    expect(row.workspace_name).toBe(UAT.workspaceName);
    expect(row.decision).toBe('permit');
    expect(row.metadata.tool_name).toBe('echo');
  });

  test('--expose uat-none adds one typed tool per upstream tool, and calling one works (issue #54 amendment: typed re-export is opt-in)', async () => {
    const session = mcpServe([listTools()], { expose: ['uat-none'] });
    expect(session.error, session.describe()).toBeNull();

    const names = toolNames(session.responses[0]);
    // The fixed six are still there — `--expose` adds, it does not replace.
    for (const fixed of FIXED_TOOLS) {
      expect(names, session.describe()).toContain(fixed);
    }

    // `<server>__<tool>`. The server segment is sanitised, so `uat-none`
    // reaches the wire as `uat-none` or `uat_none` depending on the character
    // set the product settles on; both spell the same tool.
    const exposed = names.filter((n) => /^uat[-_]none__/.test(n));
    expect(exposed, session.describe()).toHaveLength(4);
    expect(
      exposed.map((n) => n.replace(/^uat[-_]none__/, '')).sort(),
      session.describe(),
    ).toEqual(['echo', 'echo_raw_auth', 'team_notice', 'whoami']);

    const echoTool = exposed.find((n) => n.endsWith('__echo'))!;
    const listed = session.responses[0].result.tools.find((t: any) => t.name === echoTool);
    // The schema is re-exported verbatim, which is the reason to pay for it.
    expect(listed.inputSchema?.type, JSON.stringify(listed)).toBe('object');
    expect(Object.keys(listed.inputSchema.properties || {}), JSON.stringify(listed)).toContain(
      'hello',
    );
    expect(listed.description, JSON.stringify(listed)).toContain('uat-none');

    // And it is a real tool, not a listing entry: calling it reaches the mock.
    const called = mcpServe([callTool(echoTool, { hello: 'exposed' })], {
      expose: ['uat-none'],
    });
    expect(called.error, called.describe()).toBeNull();
    const result = toolResult(called.responses[0]);
    expect(result.isError ?? false, called.describe()).toBe(false);
    expect(resultText(called.responses[0]), called.describe()).toContain('exposed');
    expect(result._meta?.correlation_id, called.describe()).toBeTruthy();
  });
});

import { spawnSync } from 'child_process';
import * as path from 'path';
import { UAT } from './env';

/**
 * Drive `agentcordon mcp-serve` the way an agent runtime does: spawn it with
 * its stdin and stdout as pipes and speak newline-delimited JSON-RPC 2.0.
 *
 * The client itself is `uat/mcp_client.py`; it runs
 * `docker exec -i … agentcordon mcp-serve`, so the CLI under test sees a real
 * pipe on stdin. This module is the thin TypeScript side of it.
 */

const CLIENT = path.resolve(__dirname, '..', '..', '..', 'mcp_client.py');

export interface JsonRpcEnvelope {
  jsonrpc: string;
  id?: number;
  method?: string;
  params?: any;
  result?: any;
  error?: { code: number; message: string; data?: any };
}

export interface McpRequest {
  method: string;
  params?: any;
}

export interface McpSession {
  ok: boolean;
  argv: string[];
  initialize: any;
  initialize_error: any;
  responses: JsonRpcEnvelope[];
  notifications: JsonRpcEnvelope[];
  unparsed_stdout: string[];
  stderr: string;
  exit_code: number | null;
  error: string | null;
  /** Everything the client reported, for an assertion message. */
  describe(): string;
}

export interface McpToolResult {
  content: Array<{ type: string; text?: string; [k: string]: any }>;
  isError?: boolean;
  _meta?: Record<string, any>;
  [k: string]: any;
}

export interface ServeOptions {
  /** `--expose <server>` for each entry. */
  expose?: string[];
  /** Working directory inside the CLI container. */
  workdir?: string;
  timeoutMs?: number;
}

/**
 * Run one `mcp-serve` session: initialize, then each request in order, then
 * close stdin. Returns the raw JSON-RPC envelopes.
 */
export function mcpServe(requests: McpRequest[], opts: ServeOptions = {}): McpSession {
  const args = [CLIENT, '--container', UAT.cli];
  if (opts.workdir) args.push('--workdir', opts.workdir);
  for (const server of opts.expose ?? []) args.push('--expose', server);

  const run = spawnSync('python3', args, {
    input: JSON.stringify(requests),
    encoding: 'utf8',
    timeout: opts.timeoutMs ?? 180_000,
    maxBuffer: 32 * 1024 * 1024,
  });

  let parsed: any;
  try {
    parsed = JSON.parse(run.stdout ?? '');
  } catch {
    throw new Error(
      `uat/mcp_client.py produced no JSON (exit ${run.status}).\n` +
        `stdout: ${(run.stdout ?? '').slice(0, 4000)}\n` +
        `stderr: ${(run.stderr ?? '').slice(0, 4000)}`,
    );
  }

  const session: McpSession = {
    ...parsed,
    describe() {
      return JSON.stringify(
        {
          argv: parsed.argv,
          error: parsed.error,
          exit_code: parsed.exit_code,
          initialize: parsed.initialize,
          initialize_error: parsed.initialize_error,
          responses: parsed.responses,
          notifications: parsed.notifications,
          unparsed_stdout: parsed.unparsed_stdout,
          stderr: (parsed.stderr ?? '').slice(0, 4000),
        },
        null,
        2,
      );
    },
  };
  return session;
}

/** A `tools/list` request. */
export function listTools(): McpRequest {
  return { method: 'tools/list', params: {} };
}

/** A `tools/call` request. */
export function callTool(name: string, args: Record<string, any> = {}): McpRequest {
  return { method: 'tools/call', params: { name, arguments: args } };
}

/** The tool names a `tools/list` envelope carried, in wire order. */
export function toolNames(envelope: JsonRpcEnvelope): string[] {
  const tools = envelope?.result?.tools;
  if (!Array.isArray(tools)) {
    throw new Error(`not a tools/list result: ${JSON.stringify(envelope)}`);
  }
  return tools.map((t: any) => t.name);
}

/** The `result` of a `tools/call`, as an MCP tool result. */
export function toolResult(envelope: JsonRpcEnvelope): McpToolResult {
  if (envelope?.error) {
    throw new Error(`tools/call answered a JSON-RPC error: ${JSON.stringify(envelope.error)}`);
  }
  const result = envelope?.result;
  if (!result || !Array.isArray(result.content)) {
    throw new Error(`not a tools/call result: ${JSON.stringify(envelope)}`);
  }
  return result as McpToolResult;
}

/** Every text block of a tool result, joined — what the model would read. */
export function resultText(envelope: JsonRpcEnvelope): string {
  return toolResult(envelope)
    .content.filter((c) => typeof c.text === 'string')
    .map((c) => c.text as string)
    .join('\n');
}

/** The text content of a tool result, parsed as JSON. */
export function resultJson(envelope: JsonRpcEnvelope): any {
  const text = resultText(envelope);
  try {
    return JSON.parse(text);
  } catch (e) {
    throw new Error(`tool result text is not JSON: ${text.slice(0, 2000)}`);
  }
}

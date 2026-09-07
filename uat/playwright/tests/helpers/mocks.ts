import { spawnSync } from 'child_process';
import * as path from 'path';
import { UAT } from './env';

/** Every entry the mock IdP recorded (authorize / token / register / rotate). */
export interface IdpLogEntry {
  seq: number;
  at: number;
  kind: string;
  port: number;
  grant_type?: string;
  client_id?: string;
  has_client_secret?: boolean;
  refresh_token_presented?: string | null;
  code_verifier_presented?: boolean;
  remote_addr?: string;
  user_agent?: string | null;
  old_refresh_token?: string;
  new_refresh_token?: string;
  generation?: number;
  redirect_uris?: string[];
  request_body?: string;
  token_endpoint_auth_method?: string;
  code_challenge_method?: string | null;
  subject?: string;
  redirect_uri?: string;
  scope?: string;
}

/** Every request the mock MCP server recorded. */
export interface McpLogEntry {
  seq: number;
  at: number;
  mount: string | null;
  path: string;
  rpc_method: string | null;
  auth_seen: Record<string, { scheme?: string; value_fingerprint: string }>;
  accept: string | null;
  mcp_session_id: string | null;
  mcp_protocol_version: string | null;
}

async function getJson(url: string): Promise<any> {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${url} -> HTTP ${r.status}`);
  return r.json();
}

export async function idpLog(): Promise<IdpLogEntry[]> {
  return (await getJson(`${UAT.idpUrl}/_uat/log`)).entries as IdpLogEntry[];
}

export async function idpTokens(): Promise<any> {
  return getJson(`${UAT.idpUrl}/_uat/tokens`);
}

export async function idpClients(): Promise<any[]> {
  return (await getJson(`${UAT.idpUrl}/_uat/clients`)).clients;
}

export async function mcpLog(): Promise<McpLogEntry[]> {
  return (await getJson(`${UAT.mcpUrl}/_uat/log`)).entries as McpLogEntry[];
}

/** Token-endpoint calls only, optionally filtered by grant. */
export function tokenCalls(entries: IdpLogEntry[], grant?: string): IdpLogEntry[] {
  return entries.filter(
    (e) => e.kind === 'token' && (grant === undefined || e.grant_type === grant),
  );
}

/**
 * The mock IdP runs inside the AgentCordon server container's network
 * namespace, so a call the SERVER makes arrives from 127.0.0.1 and a call from
 * any other container (the broker, for instance) arrives from that container's
 * bridge address. This is how "the broker never called the token endpoint" is
 * measured.
 */
export function callersOtherThanTheServer(entries: IdpLogEntry[]): IdpLogEntry[] {
  return entries.filter(
    (e) =>
      (e.kind === 'token' || e.kind === 'register') &&
      e.remote_addr !== '127.0.0.1' &&
      e.remote_addr !== '::1',
  );
}

const SCRIPT = path.resolve(__dirname, '..', '..', '..', 'oauth-topology.sh');

/**
 * Recreate the server with the OAuth configuration the docs call for, then
 * start the mock IdP and the mock MCP server in its network namespace.
 */
export function oauthTopologyUp(): { code: number; out: string } {
  const r = spawnSync('bash', [SCRIPT, 'up'], {
    encoding: 'utf8',
    timeout: 300_000,
    maxBuffer: 32 * 1024 * 1024,
  });
  return { code: r.status ?? -1, out: (r.stdout ?? '') + (r.stderr ?? '') };
}

/** Poll `fn` until it returns a truthy value or the deadline passes. */
export async function until<T>(
  what: string,
  fn: () => Promise<T> | T,
  timeoutMs = 60_000,
  intervalMs = 2000,
): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  let last: unknown;
  for (;;) {
    try {
      const v = await fn();
      if (v) return v;
      last = v;
    } catch (e) {
      last = e;
    }
    if (Date.now() > deadline) {
      throw new Error(`timed out after ${timeoutMs}ms waiting for ${what} (last: ${String(last)})`);
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
}

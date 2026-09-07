import * as fs from 'fs';
import * as path from 'path';

/** uat/uat.env is the single source of truth for the topology. */
function loadEnvFile(): Record<string, string> {
  const file =
    process.env.UAT_ENV_FILE ||
    path.resolve(__dirname, '..', '..', '..', 'uat.env');
  const out: Record<string, string> = {};
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq < 0) continue;
    out[trimmed.slice(0, eq)] = trimmed.slice(eq + 1);
  }
  return out;
}

const raw = loadEnvFile();

export const UAT = {
  network: raw.UAT_NETWORK,
  volume: raw.UAT_VOLUME,
  server: raw.UAT_SERVER,
  server2: raw.UAT_SERVER2,
  upstream: raw.UAT_UPSTREAM,
  broker: raw.UAT_BROKER,
  cli: raw.UAT_CLI,
  serverImage: raw.UAT_SERVER_IMAGE,
  toolsImage: raw.UAT_TOOLS_IMAGE,
  hostPort: raw.UAT_HOST_PORT,
  serverUrl: process.env.UAT_SERVER_URL || raw.UAT_SERVER_URL,
  rootUsername: raw.UAT_ROOT_USERNAME,
  rootPassword: raw.UAT_ROOT_PASSWORD,
  masterSecret: raw.UAT_MASTER_SECRET,
  brokerSharedSecret: raw.UAT_BROKER_SHARED_SECRET,
  workspaceName: raw.UAT_WORKSPACE_NAME,
  credentialName: raw.UAT_CREDENTIAL_NAME,
  credentialSecret: raw.UAT_CREDENTIAL_SECRET,
  credentialPattern: raw.UAT_CREDENTIAL_PATTERN,

  // S11-S16: OAuth provider, mock MCP server, AWS, second workspace.
  idp: raw.UAT_IDP,
  mcp: raw.UAT_MCP,
  idpUrl: raw.UAT_IDP_URL,
  idpNoDcrUrl: raw.UAT_IDP_NODCR_URL,
  mcpUrl: raw.UAT_MCP_URL,
  mcpUpstreamHost: raw.UAT_MCP_UPSTREAM_HOST,
  baseUrl: raw.UAT_BASE_URL,
  idpDelegatedTtl: Number(raw.UAT_IDP_DELEGATED_TTL || '100'),
  idpSubject: raw.UAT_IDP_SUBJECT,
  mcpApiKey: raw.UAT_MCP_API_KEY,
  oauthCcName: raw.UAT_OAUTH_CC_NAME,
  oauthCcClientId: raw.UAT_OAUTH_CC_CLIENT_ID,
  oauthCcClientSecret: raw.UAT_OAUTH_CC_CLIENT_SECRET,
  oauthCcShortName: raw.UAT_OAUTH_CC_SHORT_NAME,
  oauthCcShortClientId: raw.UAT_OAUTH_CC_SHORT_CLIENT_ID,
  oauthCcShortClientSecret: raw.UAT_OAUTH_CC_SHORT_CLIENT_SECRET,
  oauthCcPattern: raw.UAT_OAUTH_CC_PATTERN,
  oauthManualClientId: raw.UAT_OAUTH_MANUAL_CLIENT_ID,
  oauthManualClientSecret: raw.UAT_OAUTH_MANUAL_CLIENT_SECRET,
  awsName: raw.UAT_AWS_NAME,
  awsAccessKeyId: raw.UAT_AWS_ACCESS_KEY_ID,
  awsSecretAccessKey: raw.UAT_AWS_SECRET_ACCESS_KEY,
  awsRegion: raw.UAT_AWS_REGION,
  awsService: raw.UAT_AWS_SERVICE,
  awsPattern: raw.UAT_AWS_PATTERN,
  awsDefaultName: raw.UAT_AWS_DEFAULT_NAME,
  awsRegionalHost: raw.UAT_AWS_REGIONAL_HOST,
  workspace2Name: raw.UAT_WORKSPACE2_NAME,
  workspace2Dir: raw.UAT_WORKSPACE2_DIR,

  // S17: vaults, the colleague a vault is shared with, and the operator who
  // may read the provider-client listing but not write it.
  vaultName: raw.UAT_VAULT_NAME,
  vaultRenamed: raw.UAT_VAULT_RENAMED,
  vaultCredentialName: raw.UAT_VAULT_CREDENTIAL_NAME,
  vaultCredentialSecret: raw.UAT_VAULT_CREDENTIAL_SECRET,
  shareUsername: raw.UAT_SHARE_USERNAME,
  sharePassword: raw.UAT_SHARE_PASSWORD,
  operatorUsername: raw.UAT_OPERATOR_USERNAME,
  operatorPassword: raw.UAT_OPERATOR_PASSWORD,

  // S18: the guarded broker (no --proxy-allow-loopback), its CLI container,
  // the workspace enrolled through it, and an unfenced credential that the
  // guard must still refuse.
  brokerGuarded: raw.UAT_BROKER_GUARDED,
  cliGuarded: raw.UAT_CLI_GUARDED,
  workspace3Name: raw.UAT_WORKSPACE3_NAME,
  unfencedCredentialName: raw.UAT_UNFENCED_CREDENTIAL_NAME,
  unfencedCredentialSecret: raw.UAT_UNFENCED_CREDENTIAL_SECRET,
};

/** uat/artifacts — screenshots and any evidence files land here. */
export const ARTIFACTS = path.resolve(__dirname, '..', '..', '..', 'artifacts');
export const SCREENSHOTS = path.join(ARTIFACTS, 'screenshots');

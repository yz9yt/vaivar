import path from 'path';
import { bootstrapCentral } from './app';

const CENTRAL_PORT_RAW = process.env.VAIVAR_CENTRAL_PORT || process.env.CENTRAL_PORT;
if (!CENTRAL_PORT_RAW) {
  throw new Error('VAIVAR_CENTRAL_PORT is required in central mode (declare it in the deployment YAML).');
}
const CENTRAL_PORT = parseInt(CENTRAL_PORT_RAW, 10);
if (Number.isNaN(CENTRAL_PORT) || CENTRAL_PORT <= 0 || CENTRAL_PORT > 65535) {
  throw new Error(`Invalid VAIVAR_CENTRAL_PORT: ${CENTRAL_PORT_RAW}`);
}
// Host defaults are fine; only ports must come from the deployment YAML.
const CENTRAL_HOST = process.env.VAIVAR_CENTRAL_HOST || process.env.CENTRAL_HOST || '0.0.0.0';
const CENTRAL_INGEST_TOKEN = process.env.VAIVAR_CENTRAL_INGEST_TOKEN || process.env.CENTRAL_INGEST_TOKEN || process.env.VAIVAR_API_TOKEN;
const CENTRAL_OPERATOR_TOKEN = process.env.VAIVAR_CENTRAL_OPERATOR_TOKEN || process.env.CENTRAL_OPERATOR_TOKEN || process.env.VAIVAR_API_TOKEN;
const CENTRAL_ADMIN_TOKEN = process.env.VAIVAR_CENTRAL_ADMIN_TOKEN || process.env.VAIVAR_CENTRAL_OPERATOR_TOKEN || process.env.CENTRAL_OPERATOR_TOKEN || process.env.VAIVAR_API_TOKEN;
const CENTRAL_SUPERADMIN_TOKEN = process.env.VAIVAR_CENTRAL_SUPERADMIN_TOKEN || '';
// Break-glass token (>=16 chars). Logs in as superadmin when Keycloak
// is down or for emergency access. Only used as a login fallback when
// no OIDC issuer is configured. Never appears in the UI.
const CENTRAL_BOOTSTRAP_TOKEN = process.env.VAIVAR_CENTRAL_BOOTSTRAP_TOKEN || '';
// Key used to sign the Central session cookie (>=32 hex). Set to ''
// in dev; in production set a stable value shared only with ops.
const SESSION_KEY = process.env.VAIVAR_SESSION_KEY || '';
const CENTRAL_DEV_MODE = process.env.VAIVAR_DEV_MODE === '1' || CENTRAL_OPERATOR_TOKEN === 'dev';
// Central auth mode. Default: "none" — the whole plane is served WITHOUT any
// authentication (local/dev/demo). Set to "legacy" to require the operator/
// admin/superadmin token login, or "oidc" to require Keycloak SSO.
//   none   → open access (no login, no 401)            [DEFAULT]
//   legacy → token login required (operator/admin/super)
//   oidc   → Keycloak SSO required (+ legacy fallback)
const AUTH_MODE = (process.env.VAIVAR_CENTRAL_AUTH_MODE || 'none').toLowerCase();
if (AUTH_MODE !== 'none' && AUTH_MODE !== 'legacy' && AUTH_MODE !== 'oidc') {
  throw new Error(`Invalid VAIVAR_CENTRAL_AUTH_MODE: ${AUTH_MODE} (expected "none", "legacy" or "oidc")`);
}
// Trust x-forwarded-for ONLY when Central sits behind a trusted reverse
// proxy. Enabling this with a hostile client routing through an untrusted
// hop lets attackers spoof their IP to the defense layer. Default: off.
const TRUST_PROXY = process.env.VAIVAR_TRUST_PROXY_HEADERS === '1';
const CENTRAL_KEY = process.env.VAIVAR_CENTRAL_KEY || '';
if (!CENTRAL_KEY) {
  throw new Error('VAIVAR_CENTRAL_KEY is required in central mode (generate it once and persist it).');
}
const DATA_PATH = process.env.DATA_PATH || './data/vaivar-central';
const RELEASE_DIR = process.env.VAIVAR_RELEASE_DIR || path.join(DATA_PATH, 'releases');
const INSTALLER_PATH = process.env.VAIVAR_INSTALLER_PATH || path.join(process.cwd(), 'scripts', 'honeypot-install.sh');
const NO_UPDATE_CHECK = process.env.VAIVAR_NO_UPDATE_CHECK === '1';
// When set, the SSRF guard allows private/LAN hosts (use case: Central and
// Edge honeypots on the same Docker network or same LAN, behind no proxy).
const ALLOW_PRIVATE_HOSTS = process.env.VAIVAR_ALLOW_PRIVATE_NODE_HOSTS === '1';

// OpenCTI EXTERNAL_IMPORT connector. Opt-in: only configured when both
// URL and token are present. These credentials belong only to the central
// connector and never appear on node barrier tokens.
const OPENCTI_URL = process.env.VAIVAR_OPENCTI_URL;
const OPENCTI_TOKEN = process.env.VAIVAR_OPENCTI_TOKEN;
const opencti =
  OPENCTI_URL && OPENCTI_TOKEN
    ? {
        url: OPENCTI_URL,
        token: OPENCTI_TOKEN,
        confidence: process.env.VAIVAR_OPENCTI_CONFIDENCE
          ? parseInt(process.env.VAIVAR_OPENCTI_CONFIDENCE, 10)
          : undefined,
        organizationId: process.env.VAIVAR_OPENCTI_ORG_ID || undefined,
        maxRetries: process.env.VAIVAR_OPENCTI_MAX_RETRIES
          ? parseInt(process.env.VAIVAR_OPENCTI_MAX_RETRIES, 10)
          : undefined,
        maxQueue: process.env.VAIVAR_OPENCTI_MAX_QUEUE
          ? parseInt(process.env.VAIVAR_OPENCTI_MAX_QUEUE, 10)
          : undefined,
      }
    : undefined;

// Splunk HEC export. Opt-in: only configured when both URL and token are
// present. The HEC token is a Splunk credential, never a node barrier token.
const SPLUNK_HEC_URL = process.env.VAIVAR_SPLUNK_HEC_URL;
const SPLUNK_HEC_TOKEN = process.env.VAIVAR_SPLUNK_HEC_TOKEN;
const splunk =
  SPLUNK_HEC_URL && SPLUNK_HEC_TOKEN
    ? {
        url: SPLUNK_HEC_URL,
        token: SPLUNK_HEC_TOKEN,
        index: process.env.VAIVAR_SPLUNK_HEC_INDEX || undefined,
        source: process.env.VAIVAR_SPLUNK_HEC_SOURCE || undefined,
        sourcetype: process.env.VAIVAR_SPLUNK_HEC_SOURCETYPE || undefined,
        maxRetries: process.env.VAIVAR_SPLUNK_HEC_MAX_RETRIES
          ? parseInt(process.env.VAIVAR_SPLUNK_HEC_MAX_RETRIES, 10)
          : undefined,
        maxQueue: process.env.VAIVAR_SPLUNK_HEC_MAX_QUEUE
          ? parseInt(process.env.VAIVAR_SPLUNK_HEC_MAX_QUEUE, 10)
          : undefined,
        batchSize: process.env.VAIVAR_SPLUNK_HEC_BATCH_SIZE
          ? parseInt(process.env.VAIVAR_SPLUNK_HEC_BATCH_SIZE, 10)
          : undefined,
        timeoutMs: process.env.VAIVAR_SPLUNK_HEC_TIMEOUT_MS
          ? parseInt(process.env.VAIVAR_SPLUNK_HEC_TIMEOUT_MS, 10)
          : undefined,
      }
    : undefined;

const main = async () => {
  if (!CENTRAL_INGEST_TOKEN || !CENTRAL_OPERATOR_TOKEN) {
    throw new Error('VAIVAR_CENTRAL_INGEST_TOKEN and VAIVAR_CENTRAL_OPERATOR_TOKEN are required in central mode');
  }
  const app = await bootstrapCentral({
    port: CENTRAL_PORT,
    host: CENTRAL_HOST,
    ingestToken: CENTRAL_INGEST_TOKEN,
    operatorToken: CENTRAL_OPERATOR_TOKEN,
    adminToken: CENTRAL_ADMIN_TOKEN,
    superadminToken: CENTRAL_SUPERADMIN_TOKEN,
    bootstrapToken: CENTRAL_BOOTSTRAP_TOKEN,
    sessionKey: SESSION_KEY,
    centralKey: CENTRAL_KEY,
    dbPath: DATA_PATH,
    releaseDir: RELEASE_DIR,
    installerPath: INSTALLER_PATH,
    devMode: CENTRAL_DEV_MODE,
    authMode: AUTH_MODE,
    trustProxy: TRUST_PROXY,
    splunk,
    openCTI: opencti,
    noUpdateCheck: NO_UPDATE_CHECK,
    allowPrivateHosts: ALLOW_PRIVATE_HOSTS,
  });
  await app.start();
  console.log(`central control plane listening on ${CENTRAL_HOST}:${CENTRAL_PORT}`);
  if (splunk) console.log(`Splunk HEC export enabled -> ${splunk.url}`);
  process.on('SIGINT', async () => {
    console.log('Stopping central plane...');
    await app.stop();
    process.exit(0);
  });
  process.on('SIGTERM', async () => {
    console.log('Stopping central plane...');
    await app.stop();
    process.exit(0);
  });
};

main().catch((err) => {
  console.error('Central plane failed:', err);
  process.exit(1);
});

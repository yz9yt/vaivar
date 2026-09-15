import { bootstrap } from './bootstrap';

const requiredPort = (name: string): number => {
  const raw = process.env[name];
  if (!raw) {
    throw new Error(
      `Missing required port env var ${name}. Set it in your deployment YAML (e.g. ${name}=<port>).`
    );
  }
  const value = Number(raw);
  if (!Number.isInteger(value) || value <= 0 || value > 65535) {
    throw new Error(`Invalid port for ${name}: ${raw}`);
  }
  return value;
};

// All ports are declared in the deployment YAML (docker-compose.yml) and
// passed in via env vars. Nothing is hardcoded in the runtime. In production
// the compose file enforces them as required with `:?`.
const MASTER_SECRET = process.env.VAIVAR_MASTER_SECRET ?? '';
const API_TOKEN = process.env.VAIVAR_API_TOKEN ?? '';
const HTTP_PORT = requiredPort('VAIVAR_PORT_HTTP');
const HONEYPOT_PORT = requiredPort('VAIVAR_PORT_HONEYPOT');
const CONTROL_CHANNEL = process.env.VAIVAR_CONTROL_CHANNEL ?? 'encrypted';
if (CONTROL_CHANNEL !== 'encrypted' && CONTROL_CHANNEL !== 'legacy') {
  throw new Error(`Invalid VAIVAR_CONTROL_CHANNEL: ${CONTROL_CHANNEL}`);
}

const main = async () => {
  const result = await bootstrap({
    masterSecret: MASTER_SECRET,
    apiToken: API_TOKEN,
    ports: { http: HTTP_PORT, honeypot: HONEYPOT_PORT },
    skins: ['http', 'mcp'],
    honeypotProfile: process.env.VAIVAR_HONEYPOT_PROFILE as 'all' | 'http' | 'wiki' | 'openapi' | 'mcp' | undefined,
    controlCrypto: CONTROL_CHANNEL === 'encrypted' ? { apiToken: API_TOKEN } : undefined,
  });

  if (!result.ok) {
    console.error('Failed to bootstrap vaivar:', result.error);
    process.exit(1);
  }

  const app = result.value;

  process.on('SIGINT', async () => {
    console.log('\nShutting down...');
    await app.stop();
    process.exit(0);
  });

  process.on('SIGTERM', async () => {
    console.log('\nReceived SIGTERM, shutting down...');
    await app.stop();
    process.exit(0);
  });

  process.on('uncaughtException', (err) => {
    console.error('UNCAUGHT EXCEPTION:', err);
  });

  process.on('unhandledRejection', (reason) => {
    console.error('UNHANDLED REJECTION:', reason);
  });

  try {
    const statuses = await app.start();
    console.log('vaivar started successfully:', statuses);
    console.log('Press Ctrl+C to stop');
  } catch (error) {
    console.error('Failed to start vaivar:', error);
    process.exit(1);
  }
};

main();

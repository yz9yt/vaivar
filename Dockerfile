# Build stage
FROM node:22-alpine AS builder

WORKDIR /app

# Install build tools needed for native modules (better-sqlite3)
RUN apk add --no-cache python3 make g++ sqlite-dev

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src/ ./src/

RUN npm run build
RUN npm prune --omit=dev

# Runtime stage
FROM node:22-alpine AS runtime

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Install a tiny privilege-dropping tool and the SQLite runtime library
# (the better-sqlite3 native addon needs libsqlite3 at runtime).
RUN apk add --no-cache su-exec sqlite-libs

WORKDIR /app

# Create data directory with proper permissions
RUN mkdir -p /data/vaivar /data/vaivar-central /app/logs && \
    chown -R nodejs:nodejs /data /app/logs

# Copy only production artifacts
COPY --from=builder --chown=nodejs:nodejs /app/dist/ ./dist/
COPY --from=builder --chown=nodejs:nodejs /app/package.json /app/package-lock.json ./
COPY --from=builder --chown=nodejs:nodejs /app/node_modules/ ./node_modules/
COPY --chown=nodejs:nodejs langs/ ./langs/
COPY --chown=nodejs:nodejs logos/ ./logos/
COPY --chown=nodejs:nodejs LICENSE ./LICENSE
COPY --chown=nodejs:nodejs scripts/honeypot-install.sh /app/scripts/honeypot-install.sh

# Security: read-only filesystem for application
USER nodejs

ENV NODE_ENV=production

# No ports or tokens are hardcoded here: every port is declared in the
# deployment YAML (docker-compose.yml) and passed in via env vars.

# Entrypoint fixes ownership of any root-owned named data volume, then drops
# to the unprivileged runtime user to exec the command.
COPY --chown=nodejs:nodejs docker/central-entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# Health check for container orchestration (reads the port from the deployment env).
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD node -e "const port=Number(process.env.VAIVAR_PORT_HTTP||process.env.VAIVAR_PORT_HONEYPOT);const h=require('http').request({hostname:'localhost',port,path:'/health'});h.on('error',()=>process.exit(1));h.on('response',r=>process.exit(r.statusCode===200?0:1));h.end()"

CMD ["node", "dist/app/main.js"]

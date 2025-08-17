import os, subprocess, secrets, shlex
import frappe

DOCKER_ROOT = "/opt/whatsapp-bridge"
APP_DIR = os.path.join(DOCKER_ROOT, "app")
SESSION_DIR = os.path.join(DOCKER_ROOT, "session")
LOGS_DIR = os.path.join(DOCKER_ROOT, "logs")

DEFAULT_BIND_HOST = "127.0.0.1"   # keep private; expose via nginx or SSH tunnel if needed
DEFAULT_PORT = 3001
DEFAULT_TENANT_ID = "sales"

def _ensure_dirs():
    os.makedirs(APP_DIR, exist_ok=True)
    os.makedirs(SESSION_DIR, exist_ok=True)
    os.makedirs(LOGS_DIR, exist_ok=True)

def _write(path, content, mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)
    os.chmod(path, mode)

def _dockerfile():
    return """FROM node:20-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \\
    chromium \\
    ca-certificates \\
    fonts-liberation \\
    libnss3 \\
    libatk-bridge2.0-0 \\
    libgtk-3-0 \\
    libdrm2 \\
    libxkbcommon0 \\
    libgbm1 \\
    xdg-utils \\
  && rm -rf /var/lib/apt/lists/*
ENV CHROMIUM_PATH=/usr/bin/chromium
WORKDIR /app
COPY app/package.json /app/
RUN npm install --omit=dev
COPY app/index.js /app/
VOLUME ["/app/.wwebjs_auth"]
EXPOSE 3001
CMD ["node", "index.js"]
"""

def _compose(bind_host, port, tenant_tokens):
    return f"""services:
  whatsapp-bridge:
    build: .
    container_name: whatsapp-bridge
    environment:
      - PORT=3001
      - LOG_LEVEL=info
      - CHROMIUM_PATH=/usr/bin/chromium
      - TENANT_TOKENS={tenant_tokens}
    ports:
      - "{bind_host}:{port}:3001"
    volumes:
      - ./session:/app/.wwebjs_auth
      - ./logs:/app/logs
    restart: unless-stopped
"""

def _package_json():
    return """{
  "name": "whatsapp-bridge",
  "version": "1.3.0",
  "private": true,
  "type": "module",
  "scripts": { "start": "node index.js" },
  "dependencies": {
    "dotenv": "^16.4.5",
    "express": "^4.19.2",
    "express-rate-limit": "^7.4.0",
    "helmet": "^7.1.0",
    "qrcode": "^1.5.3",
    "uuid": "^9.0.1",
    "whatsapp-web.js": "^1.26.0",
    "winston": "^3.13.0",
    "winston-daily-rotate-file": "^5.0.0"
  }
}
"""

def _index_js():
    # multi-tenant + QR auto-refresh + token-in-query for GETs
    return r"""import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import QRCode from 'qrcode';
import winston from 'winston';
import 'winston-daily-rotate-file';
import { v4 as uuidv4 } from 'uuid';
import pkg from 'whatsapp-web.js';
const { Client, LocalAuth, MessageMedia } = pkg;

const PORT = process.env.PORT || 3001;
const LOG_LEVEL = process.env.LOG_LEVEL || 'info';
const CHROMIUM_PATH = process.env.CHROMIUM_PATH || undefined;
const TENANT_TOKENS = String(process.env.TENANT_TOKENS || '').trim();

const { createLogger, transports, format } = winston;
const logger = createLogger({
  level: LOG_LEVEL,
  format: format.json(),
  transports: [new transports.Console({ format: format.simple() })]
});

const tenantTokens = {};
if (TENANT_TOKENS) {
  TENANT_TOKENS.split(',').forEach(pair => {
    const [tenant, token] = pair.split(':').map(s => s.trim());
    if (tenant && token) tenantTokens[tenant] = token;
  });
}
if (!Object.keys(tenantTokens).length) {
  logger.error('No tenants in TENANT_TOKENS');
  process.exit(1);
}

const clients = {};
const qrCache = {};
const readyState = {};

function getOrCreateClient(tenant) {
  if (clients[tenant]) return clients[tenant];
  const client = new Client({
    puppeteer: { headless: true, executablePath: CHROMIUM_PATH, args: ['--no-sandbox','--disable-setuid-sandbox'] },
    authStrategy: new LocalAuth({ clientId: `erpnext-bridge-${tenant}` })
  });
  readyState[tenant] = false;
  qrCache[tenant] = null;
  client.on('qr', async (qr) => {
    qrCache[tenant] = await QRCode.toDataURL(qr);
    logger.info(`[${tenant}] QR ready`);
  });
  client.on('ready', () => {
    readyState[tenant] = true;
    qrCache[tenant] = null;
    logger.info(`[${tenant}] WhatsApp client READY`);
  });
  client.on('disconnected', (reason) => {
    readyState[tenant] = false;
    logger.warn(`[${tenant}] Disconnected: ${reason}`);
  });
  client.initialize();
  clients[tenant] = client;
  return client;
}

const app = express();
app.use(helmet());
app.use(express.json({ limit: '25mb' }));
app.use(rateLimit({ windowMs: 60000, max: 240 }));

// auth with Bearer; for browser GETs allow ?token=
app.use((req, res, next) => {
  const isBrowserGet = req.method === 'GET' && ['/qr','/status','/health'].includes(req.path);
  const tenant = (req.query.tenant || req.body.tenant || req.headers['x-tenant'] || '').toString().trim();
  let token = '';
  const auth = req.headers.authorization || '';
  if (auth.startsWith('Bearer ')) token = auth.slice(7);
  if (!token && isBrowserGet) token = (req.query.token || '').toString().trim();
  if (!tenant || !(tenant in tenantTokens)) return res.status(400).json({ error: 'Invalid or missing tenant' });
  if (tenantTokens[tenant] !== token) return res.status(401).send('Unauthorized');
  req.tenant = tenant;
  req.client = getOrCreateClient(tenant);
  next();
});

app.get('/health', (req, res) => res.json({ ok: true, tenant: req.tenant, clientReady: !!readyState[req.tenant] }));
app.get('/status', (req, res) => res.json({ tenant: req.tenant, clientReady: !!readyState[req.tenant], lastQr: !!qrCache[req.tenant] }));

app.get('/qr', (req, res) => {
  const t = req.tenant;
  const token = (req.query.token || '').toString().trim();
  const img = qrCache[t];
  res.setHeader('Content-Type', 'text/html');
  res.end(`
<html><body style="font-family: sans-serif">
  <h3>Scan with WhatsApp (${t})</h3>
  ${img ? `<img src="${img}" />` : `<p>No QR available. Client may already be ready.</p>`}
  <script>
    const token=${JSON.stringify(token)}, tenant=${JSON.stringify(t)};
    async function poll(){
      try {
        const r = await fetch('/status?tenant='+encodeURIComponent(tenant)+'&token='+encodeURIComponent(token));
        const d = await r.json();
        if (d.clientReady) { document.body.innerHTML = '<h3>WhatsApp instance activated.</h3>'; return; }
      } catch(e){}
      setTimeout(poll, 1500);
    }
    poll();
  </script>
</body></html>`);
});

function normalizeToWhatsAppId(to){ const digits = String(to).replace(/\D/g,''); if(!digits) throw new Error('Empty phone'); return `${digits}@c.us`; }

app.post('/send', async (req, res) => {
  const tenant = req.tenant;
  const corr = uuidv4();
  try {
    if (!readyState[tenant]) return res.status(503).json({ error: `Client not ready.`, corr });
    const { to, message, media } = req.body || {};
    if (!to || (!message && !media)) return res.status(400).json({ error: 'Missing "to" and either "message" or "media".', corr });
    const chatId = normalizeToWhatsAppId(to);
    const results = [];
    if (message) {
      const msg = await req.client.sendMessage(chatId, message);
      results.push({ kind: 'text', id: msg.id.id });
    }
    if (media && Array.isArray(media.items)) {
      for (const item of media.items) {
        let mm;
        if (item.base64) {
          mm = new MessageMedia(item.mime || 'application/octet-stream', item.base64, item.filename || 'file');
        } else {
          throw new Error('Only base64 media supported in bootstrap; add URL fetch if needed');
        }
        const opts = item.caption ? { caption: item.caption } : {};
        const msg = await req.client.sendMessage(chatId, mm, opts);
        results.push({ kind: 'media', id: msg.id.id, filename: mm.filename });
      }
    }
    return res.json({ tenant, to, results, corr });
  } catch (e) {
    return res.status(500).json({ error: 'Send failed', detail: String(e?.message || e), corr });
  }
});

app.listen(PORT, () => logger.info(`whatsapp-bridge listening on :${PORT}`));
"""

def _run(cmd, cwd):
    subprocess.run(shlex.split(cmd), cwd=cwd, check=True)

def run_after_install():
    # 1) create settings single (with defaults) if missing
    if not frappe.db.exists("DocType", "WhatsApp Bridge Settings"):
        # This happens if you forgot to install fixtures for the doctype.
        # But our json below will create it once you install the app; guard anyway.
        pass

    s = frappe.get_doc({"doctype": "WhatsApp Bridge Settings"})
    if not frappe.db.exists("WhatsApp Bridge Settings"):
        # first-time defaults
        s.bridge_token = secrets.token_urlsafe(32)
        s.tenant_id = DEFAULT_TENANT_ID
        s.bind_host = DEFAULT_BIND_HOST
        s.expose_port = DEFAULT_PORT
        s.bridge_url = f"http://{DEFAULT_BIND_HOST}:{DEFAULT_PORT}/send"
        s.default_country = "Nigeria"
        s.insert(ignore_permissions=True)
    else:
        s = frappe.get_single("WhatsApp Bridge Settings")
        if not s.bridge_token:
            s.bridge_token = secrets.token_urlsafe(32)
        if not s.tenant_id:
            s.tenant_id = DEFAULT_TENANT_ID
        if not s.bind_host:
            s.bind_host = DEFAULT_BIND_HOST
        if not s.expose_port:
            s.expose_port = DEFAULT_PORT
        if not s.bridge_url:
            s.bridge_url = f"http://{s.bind_host}:{s.expose_port}/send"
        s.save(ignore_permissions=True)

    tenant_tokens = f"{s.tenant_id}:{s.bridge_token}"

    # 2) write docker project
    _ensure_dirs()
    _write(os.path.join(DOCKER_ROOT, "Dockerfile"), _dockerfile())
    _write(os.path.join(DOCKER_ROOT, "docker-compose.yml"), _compose(s.bind_host, int(s.expose_port), tenant_tokens))
    _write(os.path.join(APP_DIR, "package.json"), _package_json())
    _write(os.path.join(APP_DIR, "index.js"), _index_js())

    # 3) bring it up
    try:
        _run("docker compose down", DOCKER_ROOT)
    except Exception:
        pass
    _run("docker compose up -d --build", DOCKER_ROOT)

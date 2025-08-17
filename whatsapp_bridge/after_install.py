# whatsapp_bridge/after_install.py
# Frappe v15-compatible
import os
import re
import shlex
import shutil
import secrets
import getpass
import subprocess
import frappe

# -----------------------------
# Defaults (applied only if blank)
# -----------------------------
DEFAULT_BIND_HOST = "127.0.0.1"   # secure default
DEFAULT_PORT = 3001
DEFAULT_TENANT_ID = "sales"
DEFAULT_COUNTRY = "Nigeria"

# Project root preference
PREFERRED_ROOT = "/opt/whatsapp-bridge"


# -----------------------------
# Small helpers
# -----------------------------
def _is_root() -> bool:
    try:
        return os.geteuid() == 0
    except Exception:
        return False


def _which(cmd: str):
    return shutil.which(cmd)


def _run(cmd: str, cwd: str | None = None, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(shlex.split(cmd), cwd=cwd, check=check)


def _sudo_run(cmd: str, cwd: str | None = None, check: bool = True) -> subprocess.CompletedProcess:
    if _is_root():
        return _run(cmd, cwd=cwd, check=check)
    if not _which("sudo"):
        raise RuntimeError("sudo not available to elevate command: " + cmd)
    return subprocess.run(["sudo"] + shlex.split(cmd), cwd=cwd, check=check)


def _ensure_dir(path: str, chown_to_user: bool = False):
    try:
        os.makedirs(path, exist_ok=True)
    except PermissionError:
        _sudo_run(f"mkdir -p {shlex.quote(path)}")
    if chown_to_user:
        try:
            user = getpass.getuser()
            _sudo_run(f"chown -R {user}:{user} {shlex.quote(path)}", check=False)
            _sudo_run(f"chmod -R 775 {shlex.quote(path)}", check=False)
        except Exception:
            pass


def _write_text_file(path: str, content: str, mode: int = 0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        with open(path, "w") as f:
            f.write(content)
        os.chmod(path, mode)
    except PermissionError:
        # fallback with sudo tee
        if not _which("sudo"):
            raise
        p = subprocess.run(["sudo", "tee", path], input=content.encode("utf-8"))
        if p.returncode != 0:
            raise PermissionError(f"sudo tee failed for {path}")
        subprocess.run(["sudo", "chmod", oct(mode)[2:], path], check=False)


# -----------------------------
# Docker / Compose bootstrap
# -----------------------------
def _docker_ok() -> bool:
    return _which("docker") is not None


def _docker_access_ok() -> bool:
    try:
        subprocess.run(["docker", "ps"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False


def _compose_plugin_ok() -> bool:
    try:
        subprocess.run(["docker", "compose", "version"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False


def _compose_classic_ok() -> bool:
    return _which("docker-compose") is not None


def _compose_cmd() -> list[str]:
    if _compose_plugin_ok():
        return ["docker", "compose"]
    if _compose_classic_ok():
        return ["docker-compose"]
    frappe.throw("Docker Compose not available. Install plugin (docker compose) or classic (docker-compose).")
    return []


def _compose(cwd: str, args: list[str]):
    base = _compose_cmd()
    if _docker_access_ok():
        return subprocess.run(base + args, cwd=cwd, check=True)
    # fallback with sudo if docker group not active in this shell yet
    if _is_root():
        return subprocess.run(base + args, cwd=cwd, check=True)
    if not _which("sudo"):
        # try without check; will throw permission error above if needed
        return subprocess.run(base + args, cwd=cwd, check=True)
    return subprocess.run(["sudo"] + base + args, cwd=cwd, check=True)


def _install_docker_engine():
    # Official convenience script (idempotent enough for bootstrap)
    if _is_root():
        _run('sh -lc "curl -fsSL https://get.docker.com | sh"')
    else:
        _sudo_run('sh -lc "curl -fsSL https://get.docker.com | sh"')

    # Enable & start docker (best-effort)
    if _which("systemctl"):
        try:
            cmd = "systemctl enable --now docker"
            _sudo_run(cmd, check=False)
        except Exception:
            pass

    # Add current user to docker group (best-effort)
    try:
        user = getpass.getuser()
        if _is_root():
            _run(f"usermod -aG docker {shlex.quote(user)}", check=False)
        else:
            _sudo_run(f"usermod -aG docker {shlex.quote(user)}", check=False)
    except Exception:
        pass


def _ensure_compose_available():
    if _compose_plugin_ok() or _compose_classic_ok():
        return
    # attempt to install docker compose plugin (Debian/Ubuntu)
    if _which("apt-get"):
        try:
            if _is_root():
                _run("apt-get update", check=False)
                _run("apt-get install -y docker-compose-plugin", check=False)
            else:
                _sudo_run("apt-get update", check=False)
                _sudo_run("apt-get install -y docker-compose-plugin", check=False)
        except Exception:
            pass
    # final check
    if not (_compose_plugin_ok() or _compose_classic_ok()):
        frappe.throw("Docker Compose still not available after install attempt. Please install it and re-run.")


# -----------------------------
# Project writers
# -----------------------------
def _dockerfile() -> str:
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


def _package_json() -> str:
    return """{
  "name": "whatsapp-bridge",
  "version": "1.5.0",
  "private": true,
  "type": "module",
  "scripts": { "start": "node index.js" },
  "dependencies": {
    "dotenv": "^16.4.5",
    "express": "^4.19.2",
    "express-rate-limit": "^7.4.0",
    "helmet": "^7.1.0",
    "ipaddr.js": "^2.1.0",
    "qrcode": "^1.5.3",
    "uuid": "^9.0.1",
    "whatsapp-web.js": "^1.26.0",
    "winston": "^3.13.0"
  }
}
"""


def _index_js() -> str:
    # Includes ALLOW_IPS / ALLOW_CIDRS / ALLOW_HOSTS / TRUST_PROXY
    return r"""import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import QRCode from 'qrcode';
import winston from 'winston';
import { v4 as uuidv4 } from 'uuid';
import pkg from 'whatsapp-web.js';
import ipaddr from 'ipaddr.js';
const { Client, LocalAuth, MessageMedia } = pkg;

const PORT = process.env.PORT || 3001;
const LOG_LEVEL = process.env.LOG_LEVEL || 'info';
const CHROMIUM_PATH = process.env.CHRONIUM_PATH || process.env.CHROMIUM_PATH || undefined;
const TENANT_TOKENS = String(process.env.TENANT_TOKENS || '').trim();

const RAW_ALLOW_IPS   = (process.env.ALLOW_IPS   || '').trim();
const RAW_ALLOW_CIDRS = (process.env.ALLOW_CIDRS || '').trim();
const RAW_ALLOW_HOSTS = (process.env.ALLOW_HOSTS || '').trim();
const TRUST_PROXY = (process.env.TRUST_PROXY || '0') === '1';

const allowIPs   = RAW_ALLOW_IPS   ? RAW_ALLOW_IPS.split(',').map(s => s.trim()).filter(Boolean) : [];
const allowCIDRs = RAW_ALLOW_CIDRS ? RAW_ALLOW_CIDRS.split(',').map(s => s.trim()).filter(Boolean) : [];
const allowHosts = RAW_ALLOW_HOSTS ? RAW_ALLOW_HOSTS.split(',').map(s => s.trim().toLowerCase()).filter(Boolean) : [];

const logger = winston.createLogger({
  level: LOG_LEVEL,
  transports: [new winston.transports.Console({ format: winston.format.simple() })],
});

if (!TENANT_TOKENS) {
  logger.error('No tenants in TENANT_TOKENS');
  process.exit(1);
}

const tenantTokens = {};
TENANT_TOKENS.split(',').forEach(pair => {
  const [tenant, token] = pair.split(':').map(s => s.trim());
  if (tenant && token) tenantTokens[tenant] = token;
});

const clients = {};
const qrCache = {};
const readyState = {};

function getOrCreateClient(tenant) {
  if (clients[tenant]) return clients[tenant];
  const client = new Client({
    puppeteer: {
      headless: true,
      executablePath: CHROMIUM_PATH,
      args: ['--no-sandbox','--disable-setuid-sandbox']
    },
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
    logger.info(`[${tenant}] READY`);
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
if (TRUST_PROXY) app.set('trust proxy', true);

app.use(helmet());
app.use(express.json({ limit: '25mb' }));
app.use(rateLimit({ windowMs: 60000, max: 240 }));

function ipAllowed(ip) {
  if (!allowIPs.length && !allowCIDRs.length) return true;
  try {
    const clean = String(ip || '').replace(/^::ffff:/, '');
    if (allowIPs.includes(clean)) return true;
    const addr = ipaddr.parse(clean);
    for (const block of allowCIDRs) {
      const [range, prefixStr] = block.split('/');
      const rng = ipaddr.parse(range);
      if (rng.kind() !== addr.kind()) continue;
      if (addr.match([rng, parseInt(prefixStr, 10)])) return true;
    }
  } catch (e) {}
  return false;
}

// Network allow-lists (IP/CIDR/Host)
app.use((req, res, next) => {
  const ip = (req.ip || req.socket?.remoteAddress || '').replace(/^::ffff:/, '');
  const host = String(req.headers.host || '').toLowerCase();
  if (!ipAllowed(ip)) return res.status(403).send('Forbidden');
  if (allowHosts.length && !allowHosts.includes(host)) return res.status(403).send('Forbidden');
  next();
});

// Auth: Bearer token; allow ?token= for browser GETs to /qr|/status|/health
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

app.get('/health', (req, res) => {
  res.json({ ok: true, tenant: req.tenant, clientReady: !!readyState[req.tenant] });
});
app.get('/status', (req, res) => {
  res.json({ tenant: req.tenant, clientReady: !!readyState[req.tenant], lastQr: !!qrCache[req.tenant] });
});

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
      try{
        const r=await fetch('/status?tenant='+encodeURIComponent(tenant)+'&token='+encodeURIComponent(token));
        const d=await r.json();
        if(d.clientReady){ document.body.innerHTML='<h3>WhatsApp instance activated.</h3>'; return; }
      }catch(e){}
      setTimeout(poll,1500);
    }
    poll();
  </script>
</body></html>`);
});

function normalizeToWhatsAppId(to){
  const digits=String(to).replace(/\D/g,'');
  if(!digits) throw new Error('Empty phone');
  return `${digits}@c.us`;
}

app.post('/send', async (req, res) => {
  const tenant = req.tenant;
  const corr = uuidv4();
  try{
    if(!readyState[tenant]) return res.status(503).json({ error:'Client not ready', corr });
    const { to, message, media } = req.body || {};
    if(!to || (!message && !media)) return res.status(400).json({ error:'Missing "to" and either "message" or "media".', corr });

    const chatId = normalizeToWhatsAppId(to);
    const results = [];

    if(message){
      const msg = await req.client.sendMessage(chatId, message);
      results.push({ kind:'text', id: msg.id.id });
    }

    if(media && Array.isArray(media.items)){
      for(const item of media.items){
        if(!item.base64) throw new Error('Only base64 media supported in bootstrap');
        const mm = new MessageMedia(item.mime || 'application/octet-stream', item.base64, item.filename || 'file');
        const opts = item.caption ? { caption: item.caption } : {};
        const msg = await req.client.sendMessage(chatId, mm, opts);
        results.push({ kind:'media', id: msg.id.id, filename: mm.filename });
      }
    }

    return res.json({ tenant, to, results, corr });
  }catch(e){
    return res.status(500).json({ error:'Send failed', detail:String(e?.message || e), corr });
  }
});

app.listen(PORT, () => logger.info(`whatsapp-bridge listening on :${PORT}`));
"""


def _compose_yaml(bind_host: str, port: int, tenant_tokens: str,
                  allowed_ips: str, allowed_cidrs: str, allowed_hosts: str, trust_proxy: bool) -> str:
    return f"""services:
  whatsapp-bridge:
    build: .
    container_name: whatsapp-bridge
    environment:
      - PORT=3001
      - LOG_LEVEL=info
      - CHROMIUM_PATH=/usr/bin/chromium
      - TENANT_TOKENS={tenant_tokens}
      - ALLOW_IPS={allowed_ips}
      - ALLOW_CIDRS={allowed_cidrs}
      - ALLOW_HOSTS={allowed_hosts}
      - TRUST_PROXY={'1' if trust_proxy else '0'}
    ports:
      - "{bind_host}:{port}:3001"
    volumes:
      - ./session:/app/.wwebjs_auth
      - ./logs:/app/logs
    restart: unless-stopped
"""


# -----------------------------
# Settings helpers
# -----------------------------
def _ensure_settings_defaults_once():
    """Fill only-if-blank defaults on the Singles doctype."""
    s = frappe.get_single("WhatsApp Bridge Settings")

    if not s.get("tenant_id"):
        s.tenant_id = DEFAULT_TENANT_ID
    if not s.get("default_country"):
        s.default_country = DEFAULT_COUNTRY
    if not s.get("bind_host"):
        s.bind_host = DEFAULT_BIND_HOST
    if not s.get("expose_port"):
        s.expose_port = DEFAULT_PORT
    if not s.get("bridge_token"):
        s.bridge_token = secrets.token_urlsafe(32)
    if not s.get("bridge_url"):
        s.bridge_url = f"http://{s.bind_host}:{s.expose_port}/send"

    # Allow-list fields are optional; default to blank/false if missing
    if s.get("allowed_ips") is None:
        s.allowed_ips = ""
    if s.get("allowed_cidrs") is None:
        s.allowed_cidrs = ""
    if s.get("allowed_hosts") is None:
        s.allowed_hosts = ""
    if s.get("trust_proxy") is None:
        s.trust_proxy = 0

    s.save(ignore_permissions=True)
    return s


def _tenant_tokens_string(s) -> str:
    """
    Use multi_tenant_tokens if provided; always ensure primary tenant mapping is present/updated.
    """
    tokens = (s.get("multi_tenant_tokens") or "").strip()
    if not tokens:
        return f"{s.tenant_id}:{s.bridge_token}"

    mapping: dict[str, str] = {}
    for pair in tokens.split(","):
        p = pair.strip()
        if not p or ":" not in p:
            continue
        t, tok = p.split(":", 1)
        mapping[t.strip()] = tok.strip()

    # ensure primary is included/updated
    mapping[s.tenant_id] = s.bridge_token
    # stable order for determinism
    return ",".join(f"{t}:{mapping[t]}" for t in sorted(mapping.keys()))


# -----------------------------
# Project root creation
# -----------------------------
def _ensure_project_root() -> str:
    """
    Create /opt/whatsapp-bridge with elevation, then chown to current user so subsequent writes don't need sudo.
    Fallback to ~/whatsapp-bridge if /opt is not suitable.
    """
    user = getpass.getuser()
    try:
        if not os.path.isdir(PREFERRED_ROOT):
            _sudo_run(f"mkdir -p {shlex.quote(PREFERRED_ROOT)}")
        _sudo_run(f"chown -R {user}:{user} {shlex.quote(PREFERRED_ROOT)}", check=False)
        _sudo_run(f"chmod -R 775 {shlex.quote(PREFERRED_ROOT)}", check=False)
        # subdirs owned by user
        for sub in ("app", "session", "logs"):
            _ensure_dir(os.path.join(PREFERRED_ROOT, sub), chown_to_user=True)
        return PREFERRED_ROOT
    except Exception:
        # fallback
        home_root = os.path.join(os.path.expanduser("~"), "whatsapp-bridge")
        for sub in ("", "app", "session", "logs"):
            _ensure_dir(os.path.join(home_root, sub), chown_to_user=True)
        return home_root


# -----------------------------
# Main entry
# -----------------------------
def run_after_install():
    try:
        # 1) settings (first-install semantics)
        s = _ensure_settings_defaults_once()

        # 2) docker + compose
        if not _docker_ok():
            _install_docker_engine()
        _ensure_compose_available()

        # 3) project root (owned by bench user)
        docker_root = _ensure_project_root()

        # 4) write files
        tenant_tokens = _tenant_tokens_string(s)
        _write_text_file(os.path.join(docker_root, "Dockerfile"), _dockerfile())
        _write_text_file(
            os.path.join(docker_root, "docker-compose.yml"),
            _compose_yaml(
                s.bind_host,
                int(s.expose_port),
                tenant_tokens,
                (s.get("allowed_ips") or "").strip(),
                (s.get("allowed_cidrs") or "").strip(),
                (s.get("allowed_hosts") or "").strip(),
                bool(s.get("trust_proxy")),
            ),
        )
        _write_text_file(os.path.join(docker_root, "app", "package.json"), _package_json())
        _write_text_file(os.path.join(docker_root, "app", "index.js"), _index_js())

        # 5) compose up
        try:
            _compose(docker_root, ["down"])
        except Exception:
            pass
        _compose(docker_root, ["up", "-d", "--build"])

        frappe.msgprint("WhatsApp bridge installed and started successfully.")

    except Exception:
        frappe.log_error(frappe.get_traceback(), "WhatsApp Bridge after_install failed")
        raise


def _sudo_prefix():
    # run with sudo if not root and sudo exists
    return "" if os.geteuid() == 0 else ("sudo " if shutil.which("sudo") else "")

@frappe.whitelist()
def restart_compose():
    docker_root = "/opt/whatsapp-bridge"
    # down
    subprocess.check_call(shlex.split(_sudo_prefix() + "docker compose down"), cwd=docker_root)
    # up (rebuild to pick env changes)
    subprocess.check_call(shlex.split(_sudo_prefix() + "docker compose up -d --build"), cwd=docker_root)
    return {"ok": True}
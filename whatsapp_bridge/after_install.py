# whatsapp_bridge/after_install.py
# Frappe v15-compatible: per-site WhatsApp Bridge installer
from __future__ import annotations

import os
import re
import shlex
import shutil
import secrets
import getpass
import socket
import subprocess
import string
from pathlib import Path
import grp
import frappe

# =============================
# Defaults / constants
# =============================
DEFAULT_BIND_HOST = "127.0.0.1"   # container binds loopback only
DEFAULT_PORT = 13001              # initial host port -> container:3001
DEFAULT_TENANT_ID = "sales"
DEFAULT_COUNTRY = "Nigeria"

# Public TLS listener for QR/health (shared across all sites via SNI)
PUBLIC_TLS_PORT = 3001

# Base dir for per-site bridge projects
PREFERRED_ROOT_BASE = "/opt/whatsapp-bridge"

# Nginx
NGINX_CONF_DIR = "/etc/nginx/conf.d"

# =============================
# Small helpers
# =============================
def _is_root() -> bool:
    try:
        return os.geteuid() == 0
    except Exception:
        return False

def _which(cmd: str):
    return shutil.which(cmd)

def _run(cmd: str, cwd: str | None = None, check: bool = True):
    return subprocess.run(shlex.split(cmd), cwd=cwd, check=check)

def _sudo_run(cmd: str, cwd: str | None = None, check: bool = True):
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
        if not _which("sudo"):
            raise
        p = subprocess.run(["sudo", "tee", path], input=content.encode("utf-8"))
        if p.returncode != 0:
            raise PermissionError(f"sudo tee failed for {path}")
        subprocess.run(["sudo", "chmod", oct(mode)[2:], path], check=False)

def _sudo_prefix() -> str:
    return "" if _is_root() else ("sudo " if _which("sudo") else "")

def _site_slug(site: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9.-]+", "-", site.strip())
    s = re.sub(r"-{2,}", "-", s).strip("-").lower()
    return s or "site"

# =============================
# Docker / Compose bootstrap
# =============================
def _group_exists(name: str) -> bool:
    try:
        grp.getgrnam(name)
        return True
    except KeyError:
        return False
    except Exception:
        try:
            return subprocess.run(
                ["getent", "group", name],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            ).returncode == 0
        except Exception:
            return False

def _user_in_group(user: str, group: str) -> bool:
    try:
        groups = subprocess.check_output(["id", "-nG", user]).decode().strip().split()
        return group in groups
    except Exception:
        return False

def _ensure_docker_group_and_membership():
    user = getpass.getuser()
    if not _group_exists("docker"):
        _sudo_run("groupadd docker", check=False)
    if not _user_in_group(user, "docker"):
        _sudo_run(f"usermod -aG docker {shlex.quote(user)}", check=False)

def _ensure_docker_daemon_running():
    if _which("systemctl"):
        rc = subprocess.run(["systemctl", "is-active", "--quiet", "docker"]).returncode
        if rc != 0:
            _sudo_run("systemctl start docker", check=False)
            _sudo_run("systemctl enable docker", check=False)
            return
    if _which("service"):
        _sudo_run("service docker start", check=False)

def _preflight_docker_permissions_and_daemon():
    _ensure_docker_group_and_membership()
    _ensure_docker_daemon_running()

def _docker_ok() -> bool:
    return _which("docker") is not None

def _compose_plugin_ok() -> bool:
    try:
        subprocess.run(["docker", "compose", "version"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False

def _compose_classic_ok() -> bool:
    return _which("docker-compose") is not None

def _ensure_compose_available():
    if _compose_plugin_ok() or _compose_classic_ok():
        return
    if _which("apt-get"):
        (_is_root() and _run or _sudo_run)("apt-get update", check=False)
        (_is_root() and _run or _sudo_run)("apt-get install -y docker-compose-plugin", check=False)
    if not (_compose_plugin_ok() or _compose_classic_ok()):
        frappe.throw("Docker Compose still not available after install attempt. Please install it and re-run.")

def _compose_cmd() -> list[str]:
    if _compose_plugin_ok():
        return ["docker", "compose"]
    if _compose_classic_ok():
        return ["docker-compose"]
    _ensure_compose_available()
    if _compose_plugin_ok():
        return ["docker", "compose"]
    if _compose_classic_ok():
        return ["docker-compose"]
    frappe.throw("Docker Compose is not available (plugin or classic).")
    return []

def _compose(cwd: str, args: list[str]):
    base = _compose_cmd()
    attempts: list[list[str]] = [base + args]
    if not _is_root() and _which("sudo"):
        attempts.append(["sudo", "-n"] + base + args)  # no prompt
        attempts.append(["sudo"] + base + args)        # last resort
    last = None
    for cmd in attempts:
        try:
            subprocess.check_call(cmd, cwd=cwd)
            return
        except subprocess.CalledProcessError:
            last = cmd
            continue
    frappe.throw(
        "Failed to run: <code>{}</code><br>"
        "Tip: ensure Docker is running and this user can elevate or is in the <code>docker</code> group."
        .format(" ".join(last or attempts[-1]))
    )

def _install_docker_engine():
    (_is_root() and _run or _sudo_run)('sh -lc "curl -fsSL https://get.docker.com | sh"')
    if _which("systemctl"):
        _sudo_run("systemctl enable --now docker", check=False)
    try:
        user = getpass.getuser()
        (_is_root() and _run or _sudo_run)(f"usermod -aG docker {shlex.quote(user)}", check=False)
    except Exception:
        pass

# =============================
# Writers: Docker app + Compose
# =============================
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
  "version": "1.6.0",
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

// Network allow-lists
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

def _compose_yaml(project_name: str, container_name: str, bind_host: str, host_port: int,
                  tenant_tokens: str, allowed_ips: str, allowed_cidrs: str,
                  allowed_hosts: str, trust_proxy: bool) -> str:
    return f"""name: {project_name}
services:
  whatsapp-bridge:
    build: .
    container_name: {container_name}
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
      - "{bind_host}:{host_port}:3001"
    volumes:
      - ./session:/app/.wwebjs_auth
      - ./logs:/app/logs
    restart: unless-stopped
"""

# =============================
# Settings (no password reads)
# =============================
def _ensure_settings_defaults_once():
    """
    Seed Singles with sensible defaults (only-if-blank).
    No reading of password fields here.
    """
    s = frappe.get_single("WhatsApp Bridge Settings")

    if not s.get("tenant_id"):
        s.tenant_id = DEFAULT_TENANT_ID
    if not s.get("default_country"):
        s.default_country = DEFAULT_COUNTRY
    if not s.get("bind_host"):
        s.bind_host = DEFAULT_BIND_HOST
    if not s.get("expose_port"):
        s.expose_port = DEFAULT_PORT
    if s.get("allowed_ips")   is None: s.allowed_ips   = ""
    if s.get("allowed_cidrs") is None: s.allowed_cidrs = ""
    if s.get("allowed_hosts") is None: s.allowed_hosts = ""
    if s.get("trust_proxy")   is None: s.trust_proxy   = 1  # behind nginx by default

    # Internal URL will be corrected later once we finalize host_port
    if not s.get("bridge_url"):
        s.bridge_url = f"http://{DEFAULT_BIND_HOST}:{int(s.expose_port)}/send"

    s.save(ignore_permissions=True)
    return s

# =============================
# Token management (install-time)
# =============================
def _compose_path(docker_root: str) -> str:
    return os.path.join(docker_root, "docker-compose.yml")

def _extract_token_from_compose(compose_text: str, tenant_id: string) -> str | None:
    """
    Read TENANT_TOKENS line and pull token for the given tenant.
    Example line:
      - TENANT_TOKENS=sales:abc,ops:def
    """
    m = re.search(r"^\s*-\s*TENANT_TOKENS=([^\r\n]+)$", compose_text, flags=re.MULTILINE)
    if not m:
        return None
    mapping = m.group(1).strip()
    for pair in mapping.split(","):
        if ":" not in pair:
            continue
        t, tok = pair.split(":", 1)
        if t.strip() == tenant_id:
            return tok.strip()
    return None

def _ensure_primary_token_for_site(s, docker_root: str) -> str:
    """
    Rules:
    - If docker-compose.yml exists and contains a token for s.tenant_id, reuse it (no Password reads).
    - Else generate a new one, set in Singles via frappe.db.set_value, return it.
    """
    compose_file = _compose_path(docker_root)
    tenant_id = (s.tenant_id or DEFAULT_TENANT_ID).strip()
    if os.path.exists(compose_file):
        try:
            with open(compose_file, "r") as f:
                txt = f.read()
            tok = _extract_token_from_compose(txt, tenant_id)
            if tok:
                return tok
        except Exception:
            pass

    # Generate new token (install-time) and write to Singles without reading it
    token_plain = secrets.token_urlsafe(32)
    frappe.db.set_value("WhatsApp Bridge Settings", "WhatsApp Bridge Settings", "bridge_token", token_plain)
    try:
        frappe.db.commit()
    except Exception:
        pass
    return token_plain

def _tenant_tokens_env(primary_tenant: str, primary_token: str, s) -> str:
    """
    Build TENANT_TOKENS value without reading any password fields.
    Includes optional plain extra entries from s.multi_tenant_tokens (Data).
    """
    mapping = {primary_tenant: primary_token}
    extra = (s.get("multi_tenant_tokens") or "").strip()
    if extra:
        for pair in extra.split(","):
            p = pair.strip()
            if not p or ":" not in p:
                continue
            t, tok = p.split(":", 1)
            t, tok = t.strip(), tok.strip()
            # ignore obviously masked values like "********"
            if not tok or set(tok) == {"*"}:
                continue
            mapping[t] = tok
    # stable order
    return ",".join(f"{t}:{mapping[t]}" for t in sorted(mapping.keys()))

# =============================
# Bench / cert discovery (nginx)
# =============================
def _bench_root_and_name() -> tuple[str, str]:
    app_path = Path(frappe.get_app_path("whatsapp_bridge")).resolve()
    cur = app_path
    for _ in range(6):
        if (cur / "sites").is_dir() and (cur / "apps").is_dir():
            return str(cur), cur.name
        cur = cur.parent
    # fallback
    try:
        bench_root = app_path.parents[2]
    except IndexError:
        bench_root = app_path.parent
    return str(bench_root), bench_root.name

def _bench_nginx_conf_path(bench_name: str) -> str:
    return os.path.join(NGINX_CONF_DIR, f"{bench_name}.conf")

def _extract_cert_block_for_site(bench_conf_path: str, site: str) -> dict | None:
    if not os.path.exists(bench_conf_path):
        return None
    with open(bench_conf_path, "r") as f:
        content = f.read()

    # split into "server { ... }" blocks
    blocks = []
    i = 0
    while True:
        start = content.find("server {", i)
        if start == -1:
            break
        depth = 0
        j = start
        while j < len(content):
            ch = content[j]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    j += 1
                    break
            j += 1
        blocks.append(content[start:j])
        i = j

    target = None
    for b in blocks:
        if re.search(rf"set\s+\$site_name\s+{re.escape(site)}\s*;", b):
            target = b
            break
    if not target:
        for b in blocks:
            if "ssl_certificate " in b and "ssl_certificate_key " in b:
                target = b
                break
    if not target:
        return None

    def _rex(pat):
        m = re.search(pat, target, flags=re.MULTILINE)
        return m.group(1).strip() if m else None

    server_name = _rex(r"^\s*server_name\s+([^;]+);")
    ssl_cert = _rex(r"^\s*ssl_certificate\s+([^\s;]+)\s*;")
    ssl_key = _rex(r"^\s*ssl_certificate_key\s+([^\s;]+)\s*;")
    include_opts = _rex(r"^\s*include\s+(/etc/letsencrypt/options-ssl-nginx\.conf)\s*;")
    dhparam = _rex(r"^\s*ssl_dhparam\s+([^\s;]+)\s*;")

    if not (server_name and ssl_cert and ssl_key):
        return None
    server_name = server_name.split()[0]
    return {
        "server_name": server_name,
        "ssl_certificate": ssl_cert,
        "ssl_certificate_key": ssl_key,
        "include_options": include_opts,
        "ssl_dhparam": dhparam,
    }

# =============================
# Nginx writer & reloader (per-site)
# =============================
def _nginx_vhost_path_for_site(site: str) -> str:
    return os.path.join(NGINX_CONF_DIR, f"wa-bridge-{_site_slug(site)}.conf")

def _nginx_available() -> bool:
    return os.path.isdir(NGINX_CONF_DIR) and _which("nginx") is not None

def _write_nginx_vhost(site: str, bind_ip: str, listen_port: int, server_name: str,
                       cert: str, key: str, include_options: str | None, dhparam: str | None,
                       upstream_host: str, upstream_port: int):
    path = _nginx_vhost_path_for_site(site)

    tls_lines = [f"ssl_certificate {cert};", f"ssl_certificate_key {key};"]
    if include_options:
        tls_lines.append(f"include {include_options};")
    else:
        tls_lines += [
            "ssl_protocols TLSv1.2 TLSv1.3;",
            "ssl_ciphers HIGH:!aNULL:!MD5:!3DES;",
            "ssl_prefer_server_ciphers off;",
        ]
    if dhparam:
        tls_lines.append(f"ssl_dhparam {dhparam};")

    conf = f"""# Managed by whatsapp_bridge (site: {site})
server {{
    listen {bind_ip}:{listen_port} ssl;
    server_name {server_name};

    {chr(10).join("    " + l for l in tls_lines)}

    client_max_body_size 25m;

    proxy_http_version 1.1;
    proxy_set_header Upgrade            $http_upgrade;
    proxy_set_header Connection         "upgrade";
    proxy_set_header Host               $host;
    proxy_set_header X-Forwarded-For    $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto  $scheme;
    proxy_read_timeout 60s;
    proxy_buffering off;

    location = /qr     {{ proxy_pass http://{upstream_host}:{upstream_port}/qr; }}
    location = /status {{ proxy_pass http://{upstream_host}:{upstream_port}/status; }}
    location = /health {{ proxy_pass http://{upstream_host}:{upstream_port}/health; }}

    location ^~ /send  {{ return 403; }}
    location /         {{ return 404; }}
}}
"""
    _write_text_file(path, conf)
    frappe.msgprint(f"Wrote Nginx vhost: {path}")

def _nginx_reload():
    if not _nginx_available():
        return
    subprocess.check_call(shlex.split(_sudo_prefix() + "nginx -t"))
    if _which("systemctl"):
        subprocess.run(shlex.split(_sudo_prefix() + "systemctl reload nginx"), check=False)
    else:
        subprocess.run(shlex.split(_sudo_prefix() + "nginx -s reload"), check=False)

# =============================
# Port helpers
# =============================
def _port_in_use(host: str, port: int) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.4)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return True

def _next_free_port(host: str, start: int, limit: int = 200) -> int:
    p = start
    for _ in range(limit):
        if not _port_in_use(host, p):
            return p
        p += 1
    return start

# =============================
# Project root (per-site)
# =============================
def _ensure_project_root_for_site(site: str) -> str:
    slug = _site_slug(site)
    preferred = os.path.join(PREFERRED_ROOT_BASE, slug)
    user = getpass.getuser()
    try:
        if not os.path.isdir(preferred):
            _sudo_run(f"mkdir -p {shlex.quote(preferred)}")
        _sudo_run(f"chown -R {user}:{user} {shlex.quote(preferred)}", check=False)
        _sudo_run(f"chmod -R 775 {shlex.quote(preferred)}", check=False)
        for sub in ("app", "session", "logs"):
            _ensure_dir(os.path.join(preferred, sub), chown_to_user=True)
        return preferred
    except Exception:
        home_root = os.path.join(os.path.expanduser("~"), "whatsapp-bridge", slug)
        for sub in ("", "app", "session", "logs"):
            _ensure_dir(os.path.join(home_root, sub), chown_to_user=True)
        return home_root

# =============================
# Public IP helper
# =============================
def _detect_public_ip() -> str:
    for probe in ("1.1.1.1", "8.8.8.8"):
        try:
            out = subprocess.check_output(shlex.split(f"ip route get {probe}"), stderr=subprocess.DEVNULL).decode()
            m = re.search(r"\bsrc\s+(\d+\.\d+\.\d+\.\d+)\b", out)
            if m:
                return m.group(1)
        except Exception:
            pass
    try:
        out = subprocess.check_output(["hostname", "-I"]).decode().strip()
        cand = [x for x in out.split() if re.match(r"^\d+\.\d+\.\d+\.\d+$", x)]
        if cand:
            return cand[0]
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        pass
    return "0.0.0.0"

# =============================
# Main entry
# =============================
def run_after_install():
    try:
        site = frappe.local.site
        slug = _site_slug(site)

        # 1) Ensure Singles defaults (no password reads)
        s = _ensure_settings_defaults_once()

        # Always use loopback for container bind (public is via Nginx)
        if s.bind_host != "127.0.0.1":
            s.bind_host = "127.0.0.1"
            s.save(ignore_permissions=True)

        # 2) Docker/Compose preflight
        _preflight_docker_permissions_and_daemon()
        if not _docker_ok():
            _install_docker_engine()
        _ensure_compose_available()

        # 3) per-site project root
        docker_root = _ensure_project_root_for_site(site)

        # 4) Stop any existing stack first (so port test isn't confused)
        try:
            _compose(docker_root, ["down"])
        except Exception:
            pass

        # 5) Per-site upstream host port (loopback) – auto-bump if busy
        host_port = int(s.expose_port or DEFAULT_PORT)
        if _port_in_use("127.0.0.1", host_port):
            new_port = _next_free_port("127.0.0.1", host_port)
            if new_port != host_port:
                old = host_port
                host_port = new_port
                s.expose_port = host_port
                s.bridge_url = f"http://{s.bind_host}:{host_port}/send"
                s.save(ignore_permissions=True)
                frappe.msgprint(f"Port {old} is busy; using {host_port} for site {site}.")

        # 6) Token: generate at install-time (or reuse from compose), and write to Singles via db.set_value
        primary_token = _ensure_primary_token_for_site(s, docker_root)
        tenant_tokens_env = _tenant_tokens_env(s.tenant_id, primary_token, s)

        # 7) Write files (per-site names)
        project_name = f"wa-bridge-{slug}"
        container_name = f"whatsapp-bridge-{slug}"

        _write_text_file(os.path.join(docker_root, "Dockerfile"), _dockerfile())
        _write_text_file(os.path.join(docker_root, "app", "package.json"), _package_json())
        _write_text_file(os.path.join(docker_root, "app", "index.js"), _index_js())
        _write_text_file(
            _compose_path(docker_root),
            _compose_yaml(
                project_name=project_name,
                container_name=container_name,
                bind_host=s.bind_host,
                host_port=host_port,
                tenant_tokens=tenant_tokens_env,           # <-- PLAINTEXT mapping
                allowed_ips=(s.get("allowed_ips") or "").strip(),
                allowed_cidrs=(s.get("allowed_cidrs") or "").strip(),
                allowed_hosts=(s.get("allowed_hosts") or "").strip(),
                trust_proxy=bool(s.get("trust_proxy")),
            ),
        )

        # 8) Compose up (per-site)
        _compose(docker_root, ["up", "-d", "--build"])

        # 9) Nginx vhost (shared public port 3001, SNI via server_name)
        bench_root, bench_name = _bench_root_and_name()
        bench_conf = _bench_nginx_conf_path(bench_name)
        cert_info = _extract_cert_block_for_site(bench_conf, site)
        if cert_info:
            bind_ip = _detect_public_ip()
            _write_nginx_vhost(
                site=site,
                bind_ip=bind_ip,
                listen_port=PUBLIC_TLS_PORT,      # shared public port across sites
                server_name=cert_info["server_name"],
                cert=cert_info["ssl_certificate"],
                key=cert_info["ssl_certificate_key"],
                include_options=cert_info.get("include_options"),
                dhparam=cert_info.get("ssl_dhparam"),
                upstream_host=s.bind_host,        # 127.0.0.1
                upstream_port=host_port,          # per-site unique
            )
            _nginx_reload()
        else:
            frappe.msgprint(
                f"Could not detect certs/server_name in {bench_conf} for site {site}. "
                f"Skipping Nginx vhost creation."
            )

        frappe.msgprint(f"WhatsApp bridge installed for site {site} and started successfully.")

    except Exception:
        frappe.log_error(frappe.get_traceback(), "WhatsApp Bridge after_install failed")
        raise

@frappe.whitelist()
def restart_compose():
    site = frappe.local.site
    docker_root = _ensure_project_root_for_site(site)
    try:
        _compose(docker_root, ["down"])
    except Exception:
        pass
    _compose(docker_root, ["up", "-d", "--build"])
    return {"ok": True}

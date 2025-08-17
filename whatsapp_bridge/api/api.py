# apps/whatsapp_bridge/whatsapp_bridge/api.py
import os, re, subprocess, getpass, secrets
import frappe

PREFERRED_ROOT = "/opt/whatsapp-bridge"

def _home_root():
    return os.path.join(os.path.expanduser("~"), "whatsapp-bridge")

def _resolve_root():
    return PREFERRED_ROOT if os.path.isdir(PREFERRED_ROOT) else _home_root()

def _which(cmd):
    from shutil import which
    return which(cmd)

def _compose_cmd():
    try:
        subprocess.run(["docker", "compose", "version"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return ["docker", "compose"]
    except Exception:
        pass
    if _which("docker-compose"):
        return ["docker-compose"]
    frappe.throw("Docker Compose not found (plugin or classic). Make sure Docker is installed and the bench user is in the docker group.")

def _run(cmd, cwd=None, check=True):
    return subprocess.run(cmd, cwd=cwd, check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def _compose(args, cwd):
    return _run(_compose_cmd() + args, cwd=cwd, check=True)

def _compose_yaml(bind_host, port, tenant_tokens):
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

def _tenant_tokens_string(s):
    tokens = (s.get("multi_tenant_tokens") or "").strip()
    if not tokens:
        return f"{s.tenant_id}:{s.bridge_token}"
    # ensure the primary tenant is included/updated
    mapping = {}
    for pair in tokens.split(","):
        pair = pair.strip()
        if not pair or ":" not in pair:
            continue
        t, tok = pair.split(":", 1)
        mapping[t.strip()] = tok.strip()
    mapping[s.tenant_id] = s.bridge_token
    return ",".join(f"{t}:{tok}" for t, tok in mapping.items())

def _rewrite_compose(s):
    root = _resolve_root()
    yml = _compose_yaml(
        s.bind_host, int(s.expose_port), _tenant_tokens_string(s),
        (s.get("allowed_ips") or "").strip(),
        (s.get("allowed_cidrs") or "").strip(),
        (s.get("allowed_hosts") or "").strip(),
        bool(s.get("trust_proxy"))
    )
    compose_path = os.path.join(root, "docker-compose.yml")
    os.makedirs(root, exist_ok=True)
    with open(compose_path, "w") as f:
        f.write(yml)
    return root, compose_path


@frappe.whitelist()
def bridge_status():
    try:
        ps = _run(["docker", "ps", "--filter", "name=whatsapp-bridge", "--format", "{{.Names}} {{.Status}}"])
        out = (ps.stdout or "").strip()
        return {"running": out.startswith("whatsapp-bridge "), "message": out or "not running"}
    except Exception as e:
        return {"running": False, "message": f"error: {e}"}

@frappe.whitelist()
def restart_bridge():
    root = _resolve_root()
    try:
        try:
            _compose(["down"], cwd=root)
        except Exception:
            pass
        r = _compose(["up", "-d", "--build"], cwd=root)
        return {"ok": True, "message": (r.stdout or "restarted").strip()}
    except subprocess.CalledProcessError as e:
        frappe.throw(f"Compose restart failed:\n{e.stderr or e.stdout or e}")
    except Exception as e:
        frappe.throw(f"Restart failed: {e}")

@frappe.whitelist()
def apply_settings():
    """
    Rewrite docker-compose.yml from current settings and restart the bridge.
    """
    s = frappe.get_single("WhatsApp Bridge Settings")
    root, _ = _rewrite_compose(s)
    try:
        try:
            _compose(["down"], cwd=root)
        except Exception:
            pass
        r = _compose(["up", "-d", "--build"], cwd=root)
        return {"ok": True, "message": (r.stdout or "applied & restarted").strip()}
    except subprocess.CalledProcessError as e:
        frappe.throw(f"Compose apply failed:\n{e.stderr or e.stdout or e}")
    except Exception as e:
        frappe.throw(f"Apply failed: {e}")

@frappe.whitelist()
def rotate_token():
    s = frappe.get_single("WhatsApp Bridge Settings")
    s.bridge_token = secrets.token_urlsafe(32)
    s.save(ignore_permissions=True)
    # apply new tokens into compose and restart
    return apply_settings()

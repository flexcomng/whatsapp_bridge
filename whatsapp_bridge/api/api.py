# apps/whatsapp_bridge/whatsapp_bridge/api.py
import os
import re
import shlex
import subprocess
import secrets
from pathlib import Path
import frappe

# -----------------------------
# Per-site roots & constants
# -----------------------------
PREFERRED_ROOT_BASE = "/opt/whatsapp-bridge"  # each site: /opt/whatsapp-bridge/<site-slug>

def _site() -> str:
    return frappe.local.site

def _site_slug(site: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9.-]+", "-", site.strip())
    s = re.sub(r"-{2,}", "-", s).strip("-").lower()
    return s or "site"

def _root_for_site(site: str) -> str:
    slug = _site_slug(site)
    preferred = os.path.join(PREFERRED_ROOT_BASE, slug)
    if os.path.isdir(preferred):
        return preferred
    # fallback to home if /opt/<slug> not present
    return os.path.join(os.path.expanduser("~"), "whatsapp-bridge", slug)

# -----------------------------
# Docker / Compose helpers
# -----------------------------
def _which(cmd: str):
    from shutil import which
    return which(cmd)

def _compose_cmd() -> list[str]:
    # prefer docker compose plugin
    try:
        subprocess.run(["docker", "compose", "version"], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return ["docker", "compose"]
    except Exception:
        pass
    if _which("docker-compose"):
        return ["docker-compose"]
    frappe.throw("Docker Compose not found (plugin or classic). "
                 "Install Docker and ensure the bench user can run it.")

def _compose(args: list[str], cwd: str):
    """
    Try compose without sudo, then sudo -n (no prompt), then sudo (interactive shells).
    """
    base = _compose_cmd()
    candidates = [base + args]
    if os.geteuid() != 0 and _which("sudo"):
        candidates.append(["sudo", "-n"] + base + args)
        candidates.append(["sudo"] + base + args)

    last_err = None
    for cmd in candidates:
        try:
            return subprocess.run(cmd, cwd=cwd, check=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        except subprocess.CalledProcessError as e:
            last_err = e
            continue

    # If all failed, surface a helpful error
    msg = (last_err.stderr or last_err.stdout or str(last_err)) if last_err else "unknown error"
    frappe.throw("Failed to run: <code>{}</code><br>{}".format(" ".join(candidates[-1]), frappe.utils.escape_html(msg)))

# -----------------------------
# Compose file generation
# -----------------------------
def _compose_yaml(project_name: str, container_name: str, bind_host: str, host_port: int,
                  tenant_tokens: str, allowed_ips: str, allowed_cidrs: str,
                  allowed_hosts: str, trust_proxy: bool) -> str:
    # Compose v2 supports top-level "name:" to set the project name
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

def _tenant_tokens_string(s) -> str:
    """
    Build TENANT_TOKENS as plaintext: "<tenant_id>:<token>[,extra:tok...]".
    - Primary token comes from the Password field via get_password().
    - Extra entries from 'multi_tenant_tokens' are accepted as-is, but any
      obviously masked ('********') tokens are ignored.
    """
    tenant = (s.tenant_id or "").strip()
    primary = (s.get_password("bridge_token", raise_exception=False) or "").strip()
    if not tenant or not primary:
        frappe.throw("Tenant ID or bridge token is missing in Settings.")

    mapping = {tenant: primary}

    raw_multi = (s.get("multi_tenant_tokens") or "").strip()
    if raw_multi:
        for pair in raw_multi.split(","):
            p = pair.strip()
            if not p or ":" not in p:
                continue
            t, tok = p.split(":", 1)
            t, tok = t.strip(), tok.strip()
            if not t or not tok:
                continue
            # ignore fully masked tokens like "********"
            if set(tok) == {"*"}:
                continue
            mapping[t] = tok

    # stable order for determinism
    return ",".join(f"{t}:{mapping[t]}" for t in sorted(mapping.keys()))

def _rewrite_compose_for_site(s) -> tuple[str, str]:
    """
    Write (or rewrite) docker-compose.yml for the current site from settings.
    Returns (root_dir, compose_path).
    """
    site = _site()
    slug = _site_slug(site)
    root = _root_for_site(site)

    os.makedirs(root, exist_ok=True)

    project_name  = f"wa-bridge-{slug}"
    container_name = f"whatsapp-bridge-{slug}"

    bind_host  = (s.bind_host or "127.0.0.1").strip()  # container binds loopback
    host_port  = int(s.expose_port or 13001)

    tenant_tokens = _tenant_tokens_string(s)
    yml = _compose_yaml(
        project_name=project_name,
        container_name=container_name,
        bind_host=bind_host,
        host_port=host_port,
        tenant_tokens=tenant_tokens,
        allowed_ips=(s.get("allowed_ips") or "").strip(),
        allowed_cidrs=(s.get("allowed_cidrs") or "").strip(),
        allowed_hosts=(s.get("allowed_hosts") or "").strip(),
        trust_proxy=bool(s.get("trust_proxy")),
    )

    compose_path = os.path.join(root, "docker-compose.yml")
    with open(compose_path, "w") as f:
        f.write(yml)

    return root, compose_path

# -----------------------------
# Public API
# -----------------------------
@frappe.whitelist()
def bridge_status():
    """
    Report running status for the current site's container.
    """
    try:
        site = _site()
        slug = _site_slug(site)
        # Filter by the exact per-site container name
        ps = subprocess.run(
            ["docker", "ps", "--filter", f"name=whatsapp-bridge-{slug}", "--format", "{{.Names}} {{.Status}}"],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        out = (ps.stdout or "").strip()
        return {
            "running": out.startswith(f"whatsapp-bridge-{slug} "),
            "message": out or "not running"
        }
    except Exception as e:
        return {"running": False, "message": f"error: {e}"}

@frappe.whitelist()
def restart_bridge():
    """
    Restart (rebuild) the current site's bridge using existing compose file.
    """
    root = _root_for_site(_site())
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
    Rewrite docker-compose.yml from current settings (for this site) and restart.
    Ensures the plaintext token from the Password field is written to TENANT_TOKENS.
    """
    s = frappe.get_single("WhatsApp Bridge Settings")
    root, _ = _rewrite_compose_for_site(s)
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
    """
    Generate a fresh token for this site, save it in Singles (Password field),
    rewrite compose with the new plaintext token, and restart.
    """
    new_tok = secrets.token_urlsafe(32)
    # Save directly to the Singles row; Frappe encrypts Password fields on save.
    frappe.db.set_value("WhatsApp Bridge Settings", None, "bridge_token", new_tok)
    frappe.db.commit()

    # Now apply (rewrite compose with plaintext token + restart)
    return apply_settings()

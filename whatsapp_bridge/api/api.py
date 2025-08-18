# apps/whatsapp_bridge/whatsapp_bridge/api.py
import os, re, shlex, subprocess, shutil, getpass, secrets, socket
from pathlib import Path
import frappe

# -----------------------------
# Constants / paths
# -----------------------------
PUBLIC_TLS_PORT = 3001                    # external nginx -> bridge port (shared)
PREFERRED_ROOT_BASE = "/opt/whatsapp-bridge"  # per-site subdir root


# -----------------------------
# Small helpers
# -----------------------------
def _which(cmd: str):
    from shutil import which
    return which(cmd)

def _run(cmd, cwd=None, check=True):
    return subprocess.run(cmd, cwd=cwd, check=check,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def _sudo_prefix():
    return "" if os.geteuid() == 0 else ("sudo " if _which("sudo") else "")

def _site_slug(site: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9.-]+", "-", (site or "").strip())
    s = re.sub(r"-{2,}", "-", s).strip("-").lower()
    return s or "site"

def _bench_site() -> str:
    # running inside bench; frappe.local.site is reliable here
    return frappe.local.site

def _project_root_for_site(site: str) -> str:
    slug = _site_slug(site)
    base = PREFERRED_ROOT_BASE if os.path.isdir("/opt") else os.path.join(os.path.expanduser("~"), "whatsapp-bridge")
    root = os.path.join(base, slug)
    # ensure dirs exist and are owned by bench user
    os.makedirs(os.path.join(root, "app"), exist_ok=True)
    os.makedirs(os.path.join(root, "session"), exist_ok=True)
    os.makedirs(os.path.join(root, "logs"), exist_ok=True)
    try:
        user = getpass.getuser()
        if _sudo_prefix():
            subprocess.run(shlex.split(_sudo_prefix() + f"chown -R {user}:{user} {shlex.quote(root)}"), check=False)
            subprocess.run(shlex.split(_sudo_prefix() + f"chmod -R 775 {shlex.quote(root)}"), check=False)
    except Exception:
        pass
    return root


# -----------------------------
# Docker / compose preflight
# -----------------------------
def _compose_cmd():
    # prefer plugin
    try:
        subprocess.run(["docker", "compose", "version"], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return ["docker", "compose"]
    except Exception:
        pass
    if _which("docker-compose"):
        return ["docker-compose"]
    frappe.throw("Docker Compose not found (plugin or classic). Install docker and the compose plugin.")
    return []

def _compose(args, cwd):
    """
    Try compose 3 ways:
      1) no sudo
      2) sudo -n (non-interactive)
      3) sudo (interactive; may fail in bench)
    """
    base = _compose_cmd()
    candidates = [base + args]
    if os.geteuid() != 0 and _which("sudo"):
        candidates.append(["sudo", "-n"] + base + args)
        candidates.append(["sudo"] + base + args)

    last = None
    for cmd in candidates:
        try:
            return _run(cmd, cwd=cwd, check=True)
        except subprocess.CalledProcessError as e:
            last = e
            continue

    # Build a helpful error
    hint = "Tip: ensure Docker is running and this user can elevate or is in the docker group."
    if last:
        raise frappe.ValidationError(
            f"Failed to run: {' '.join(candidates[-1])}\n{hint}\n\nSTDERR:\n{(last.stderr or '').strip()}\nSTDOUT:\n{(last.stdout or '').strip()}"
        )
    else:
        raise frappe.ValidationError(f"Failed to run: {' '.join(candidates[-1])}\n{hint}")

def _preflight_docker():
    # Start daemon if needed
    try:
        if _which("systemctl"):
            rc = subprocess.run(["systemctl", "is-active", "--quiet", "docker"]).returncode
            if rc != 0:
                subprocess.run(shlex.split(_sudo_prefix() + "systemctl enable --now docker"), check=False)
        elif _which("service"):
            subprocess.run(shlex.split(_sudo_prefix() + "service docker start"), check=False)
    except Exception:
        pass
    # Add user to docker group (effective next login/newgrp)
    try:
        user = getpass.getuser()
        groups = subprocess.check_output(["id", "-nG", user]).decode().strip().split()
        if "docker" not in groups and _which("sudo"):
            subprocess.run(["sudo", "groupadd", "docker"], check=False)
            subprocess.run(["sudo", "usermod", "-aG", "docker", user], check=False)
    except Exception:
        pass


# -----------------------------
# Compose YAML
# -----------------------------
def _ensure_token_plain(s) -> str:
    # If blank, generate a new plaintext token and store via db.set_value (Singles name is None)
    token = s.get_password(fieldname="bridge_token", raise_exception=False)
    if not token:
        token = secrets.token_urlsafe(32)
        frappe.db.set_value("WhatsApp Bridge Settings", None, "bridge_token", token)
        frappe.db.commit()
    return token

def _tenant_tokens(s) -> str:
    """Always return plaintext TENANT_TOKENS (primary + optional extras)."""
    primary = _ensure_token_plain(s)
    mapping = {}

    extra = (s.get("multi_tenant_tokens") or "").strip()
    if extra:
        for pair in extra.split(","):
            p = pair.strip()
            if not p or ":" not in p:
                continue
            t, tok = p.split(":", 1)
            t, tok = t.strip(), tok.strip()
            if tok and set(tok) != {"*"}:
                mapping[t] = tok

    mapping[s.tenant_id] = primary
    return ",".join(f"{t}:{mapping[t]}" for t in sorted(mapping.keys()))

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

def _rewrite_compose(s):
    site = _bench_site()
    slug = _site_slug(site)
    root = _project_root_for_site(site)

    project_name = f"wa-bridge-{slug}"
    container_name = f"whatsapp-bridge-{slug}"

    tenant_tokens = _tenant_tokens(s)

    yml = _compose_yaml(
        project_name=project_name,
        container_name=container_name,
        bind_host=s.bind_host or "127.0.0.1",
        host_port=int(s.expose_port or 13001),
        tenant_tokens=tenant_tokens,
        allowed_ips=(s.get("allowed_ips") or "").strip(),
        allowed_cidrs=(s.get("allowed_cidrs") or "").strip(),
        allowed_hosts=(s.get("allowed_hosts") or "").strip(),
        trust_proxy=bool(s.get("trust_proxy")),
    )
    compose_path = os.path.join(root, "docker-compose.yml")
    with open(compose_path, "w") as f:
        f.write(yml)
    return root, container_name


# -----------------------------
# Public API
# -----------------------------
@frappe.whitelist()
def bridge_status():
    """Return running status for the per-site container."""
    try:
        site = _bench_site()
        slug = _site_slug(site)
        cname = f"whatsapp-bridge-{slug}"
        ps = _run(["docker", "ps", "--filter", f"name={cname}", "--format", "{{.Names}} {{.Status}}"])
        out = (ps.stdout or "").strip()
        return {"running": out.startswith(cname + " "), "message": out or "not running"}
    except Exception as e:
        return {"running": False, "message": f"error: {e}"}

@frappe.whitelist()
def restart_bridge():
    """Stop & start the per-site bridge (rewrites compose first to be safe)."""
    s = frappe.get_single("WhatsApp Bridge Settings")
    _ensure_token_plain(s)  # make sure a real token exists
    root, _ = _rewrite_compose(s)

    _preflight_docker()
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
    Ensures a plaintext token exists and is written into TENANT_TOKENS.
    """
    s = frappe.get_single("WhatsApp Bridge Settings")
    _ensure_token_plain(s)
    root, _ = _rewrite_compose(s)

    _preflight_docker()
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
    Generate a brand new plaintext token, store it, rewrite compose, and restart.
    """
    new_token = secrets.token_urlsafe(32)
    frappe.db.set_value("WhatsApp Bridge Settings", None, "bridge_token", new_token)
    frappe.db.commit()
    return apply_settings()

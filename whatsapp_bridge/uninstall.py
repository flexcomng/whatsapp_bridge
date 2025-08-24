# whatsapp_bridge/uninstall.py
# Cleanly tear down per-site WhatsApp Bridge resources (keep Docker engine)

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import getpass
from pathlib import Path
import re
import frappe

# Must mirror after_install constants
PREFERRED_ROOT_BASE = "/opt/whatsapp-bridge"
NGINX_CONF_DIR = "/etc/nginx/conf.d"
PUBLIC_TLS_PORT = 3001  # informational only

# ---------------- helpers ----------------
def _site_slug(site: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9.-]+", "-", site.strip())
    s = re.sub(r"-{2,}", "-", s).strip("-").lower()
    return s or "site"

def _which(cmd: str) -> str | None:
    return shutil.which(cmd)

def _is_root() -> bool:
    try:
        return os.geteuid() == 0
    except Exception:
        return False

def _sudo_prefix() -> str:
    return "" if _is_root() else ("sudo " if _which("sudo") else "")

def _compose_cmd() -> list[str]:
    # Prefer plugin; fallback to classic
    if _which("docker"):
        try:
            subprocess.run(
                ["docker", "compose", "version"],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            return ["docker", "compose"]
        except Exception:
            pass
    if _which("docker-compose"):
        return ["docker-compose"]
    # Compose not found; we can still proceed to delete files and vhost
    return []

def _compose_down(cwd: str):
    cmd = _compose_cmd()
    if not cmd:
        return
    attempts = [cmd + ["down", "--remove-orphans"]]
    if not _is_root() and _which("sudo"):
        attempts.insert(0, ["sudo", "-n"] + attempts[0])
        attempts.append(["sudo"] + attempts[-1])  # interactive fallback
    last_err = None
    for c in attempts:
        try:
            subprocess.check_call(c, cwd=cwd)
            return
        except subprocess.CalledProcessError as e:
            last_err = e
            continue
    # Don’t fail uninstall if compose down didn’t work; just log
    frappe.log_error(f"Compose down failed in {cwd}: {last_err}", "WA Bridge Uninstall")

def _rm_path(p: str):
    if not p or not os.path.exists(p):
        return
    try:
        shutil.rmtree(p)
    except PermissionError:
        # fallback to sudo
        subprocess.run(shlex.split(_sudo_prefix() + f"rm -rf {shlex.quote(p)}"), check=False)

def _nginx_reload():
    if not (_which("nginx") and os.path.isdir(NGINX_CONF_DIR)):
        return
    # validate, then reload
    subprocess.run(shlex.split(_sudo_prefix() + "nginx -t"), check=False)
    if _which("systemctl"):
        subprocess.run(shlex.split(_sudo_prefix() + "systemctl reload nginx"), check=False)
    else:
        subprocess.run(shlex.split(_sudo_prefix() + "nginx -s reload"), check=False)

def _docker_rm_images_for_project(slug: str):
    """
    Remove the specific image this project built, if present.
    We DO NOT touch the Docker engine or unrelated images.
    The image name pattern comes from after_install compose "name: wa-bridge-<slug>"
    and the single service "whatsapp-bridge" -> image tag:
      wa-bridge-<slug>-whatsapp-bridge
    """
    image_tag = f"wa-bridge-{slug}-whatsapp-bridge"
    if not _which("docker"):
        return
    # Check if image exists first
    try:
        out = subprocess.check_output(["docker", "images", "-q", image_tag]).decode().strip()
    except Exception:
        out = ""
    if not out:
        return
    # Try removal (ignore failure)
    subprocess.run(["docker", "rmi", "-f", image_tag], check=False)
    if not _is_root() and _which("sudo"):
        subprocess.run(["sudo", "docker", "rmi", "-f", image_tag], check=False)

# ---------------- main hook ----------------
def before_uninstall(*args, **kwargs):
    """
    Remove per-site WhatsApp Bridge resources for the current site:
      - Stop and remove compose stack (containers, networks)
      - Remove per-site project directory under /opt/whatsapp-bridge/<slug> or ~/whatsapp-bridge/<slug>
      - Remove Nginx vhost /etc/nginx/conf.d/wa-bridge-<slug>.conf and reload nginx
      - Optionally remove the project's own built image (safe, narrow tag)
    Do NOT remove Docker engine or global config.
    """
    site = getattr(frappe.local, "site", None) or frappe.get_site_path().split(os.sep)[-1]
    slug = _site_slug(site)

    # Locate existing project root WITHOUT creating anything
    preferred = os.path.join(PREFERRED_ROOT_BASE, slug)
    home_alt  = os.path.join(os.path.expanduser("~"), "whatsapp-bridge", slug)
    candidates = [preferred, home_alt]
    docker_root = next((p for p in candidates if os.path.isdir(p)), None)

    # 1) Compose down (best-effort)
    if docker_root:
        try:
            _compose_down(docker_root)
        except Exception as e:
            frappe.log_error(f"compose down error: {e}", "WA Bridge Uninstall")

    # 2) Remove nginx vhost
    vhost_path = os.path.join(NGINX_CONF_DIR, f"wa-bridge-{slug}.conf")
    if os.path.exists(vhost_path):
        try:
            subprocess.run(shlex.split(_sudo_prefix() + f"rm -f {shlex.quote(vhost_path)}"), check=False)
        except Exception as e:
            frappe.log_error(f"vhost remove error: {e}", "WA Bridge Uninstall")
        _nginx_reload()

    # 3) Remove project directory
    if docker_root:
        _rm_path(docker_root)

    # 4) Remove the per-project image (safe tag), ignore failures
    try:
        _docker_rm_images_for_project(slug)
    except Exception as e:
        frappe.log_error(f"image remove warn: {e}", "WA Bridge Uninstall")

    frappe.msgprint(f"WhatsApp Bridge resources removed for site {site} (Docker engine untouched).")

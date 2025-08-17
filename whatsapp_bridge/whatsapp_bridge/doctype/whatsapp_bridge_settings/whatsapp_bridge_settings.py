# Copyright (c) 2025, Flexcom Systems and contributors
# For license information, please see license.txt
import os, shlex, subprocess, shutil
import frappe, requests, json, base64
from frappe.model.document import Document

class WhatsAppBridgeSettings(Document):
    def on_update(self):
        """
        Whenever settings change, rewrite docker-compose and restart the bridge.
        """
        try:
            frappe.get_attr("whatsapp_bridge.api.api.apply_settings")()
            frappe.msgprint("Bridge settings applied and container restarted.")
        except Exception as e:
            frappe.log_error(frappe.get_traceback(), "WhatsApp Bridge: apply on_update failed")
            frappe.msgprint("Could not restart the bridge automatically. Check 'WhatsApp Bridge' error logs.")

def _base_url_from_send(send_url: str) -> str:
    if not send_url:
        return ""
    # normalize: http://host:3001/send -> http://host:3001/
    return send_url[:-5] if send_url.endswith("/send") else send_url.rstrip("/") + "/"


@frappe.whitelist()
def bridge_status():
    s = frappe.get_single("WhatsApp Bridge Settings")
    base = _base_url_from_send((s.bridge_url or "").strip())
    headers = {"Authorization": f"Bearer {s.bridge_token}", "X-Tenant": (s.tenant_id or "sales")}
    try:
        r = requests.get(base + "status", headers=headers, timeout=10)
        return r.json() if r.ok else {"ok": False, "error": r.text}
    except Exception as e:
        return {"ok": False, "error": str(e)}

@frappe.whitelist()
def bridge_qr_html():
    s = frappe.get_single("WhatsApp Bridge Settings")
    base = _base_url_from_send((s.bridge_url or "").strip())
    # Prefer Authorization header (server-to-server)
    headers = {"Authorization": f"Bearer {s.bridge_token}", "X-Tenant": (s.tenant_id or "sales")}
    try:
        r = requests.get(base + "qr", headers=headers, timeout=10)
        if r.ok:
            return {"html": r.text}
        return {"html": f"<p>Unable to fetch QR: {r.status_code} {r.text}</p>"}
    except Exception as e:
        return {"html": f"<p>Unable to fetch QR: {e}</p>"}


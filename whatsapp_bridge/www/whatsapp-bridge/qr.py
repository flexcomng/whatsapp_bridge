import frappe
from frappe.utils import get_url

def get_context(context):
    context.no_cache = 1
    # check bridge status; if not ready, embed QR html
    status = frappe.call("whatsapp_bridge.whatsapp_bridge.doctype.whatsapp_bridge_settings.whatsapp_bridge_settings.bridge_status")
    s = frappe.get_single("WhatsApp Bridge Settings")

    context.client_ready = bool(status and status.get("clientReady"))
    context.tenant = s.tenant_id
    context.message = "WhatsApp instance activated." if context.client_ready else "Scan the QR to activate WhatsApp."

    if not context.client_ready:
        qr = frappe.call("whatsapp_bridge.whatsapp_bridge.doctype.whatsapp_bridge_settings.whatsapp_bridge_settings.bridge_qr_html")
        context.qr_html = (qr or {}).get("html", "<p>No QR available.</p>")

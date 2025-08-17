import frappe

def get_context(context):
    context.no_cache = 1
    status = frappe.call("whatsapp_bridge.whatsapp_bridge.doctype.whatsapp_bridge_settings.whatsapp_bridge_settings.bridge_status")
    context.status = status or {}

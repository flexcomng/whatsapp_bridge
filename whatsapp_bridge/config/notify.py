# whatsapp_bridge/notify.py
import json, base64
import frappe
from frappe.utils.safe_exec import get_safe_globals

# ---------- settings ----------
def _ensure_send_url(url: str) -> str:
    if not url:
        return ""
    u = url.strip().rstrip("/")
    return u if u.endswith("/send") else (u + "/send")

def _get_settings():
    s = frappe.get_single("WhatsApp Bridge Settings")
    # bridge_token may be Password type; fetch decrypted if needed
    bridge_token = s.get_password(fieldname='bridge_token', raise_exception=False) if s.bridge_token else None
    return (
        _ensure_send_url((s.bridge_url or "").strip()),
        (bridge_token or "").strip(),
        (s.tenant_id or "").strip(),
        (s.default_country or "Nigeria").strip(),
    )

# ---------- helpers ----------
def _fmt_money(v, currency=None, precision=None):
    try:
        return frappe.utils.fmt_money(v or 0, currency=currency, precision=precision)
    except Exception:
        try:
            return f"{float(v or 0):,.2f}"
        except Exception:
            return str(v or 0)

def _render_jinja(tpl, doc):
    """Single authoritative renderer (injects fmt_money)."""
    if not tpl:
        return ""
    ctx = {
        "doc": doc,
        "fmt_money": _fmt_money,
    }
    ctx.update(get_safe_globals())
    return frappe.render_template(tpl, ctx)

def _normalize_msisdn(raw, country=None):
    if not raw:
        return None
    digits = "".join(ch for ch in str(raw) if ch.isdigit())
    c = (country or "").strip().lower()
    if c in ("nigeria", "ng"):
        if digits.startswith("0") and len(digits) == 11:
            return "234" + digits[1:]
        if digits.startswith("234"):
            return digits
    elif c in ("ghana", "gh"):
        if digits.startswith("0") and len(digits) == 10:
            return "233" + digits[1:]
        if digits.startswith("233"):
            return digits
    elif c in ("cameroon", "cm"):
        if digits.startswith("0") and len(digits) == 10:
            return "237" + digits[1:]
        if digits.startswith("237") or (len(digits) == 9 and digits.startswith("6")):
            return digits if digits.startswith("237") else "237" + digits
    return digits

def _pdf_base64(dt, name, print_format=None):
    pdf_bytes = frappe.get_print(dt, name, print_format=print_format, as_pdf=True)
    return base64.b64encode(pdf_bytes).decode("utf-8")

def _find_mobile_default(doc):
    for f in ("contact_mobile", "mobile_no", "phone"):
        v = getattr(doc, f, None)
        if v:
            return v
    if getattr(doc, "customer", None):
        m = frappe.db.get_value("Customer", doc.customer, "mobile_no")
        if m:
            return m
    return None

def _log_row(tenant_id, doctype_name, docname, to, message, has_media, status,
             corr=None, msg_ids=None, error=None):
    try:
        log = frappe.new_doc("WhatsApp Message Log")
        log.tenant_id = tenant_id
        log.doctype_name = doctype_name
        log.docname = docname
        log.to_number = to
        log.message_preview = (message or "")[:500]
        log.has_media = 1 if has_media else 0
        log.status = status  # "Success" | "Failed" | "Pending"
        log.bridge_corr_id = corr or ""
        log.bridge_msg_ids = frappe.as_json(msg_ids or [])
        log.sent_on = frappe.utils.now_datetime()
        if error:
            log.error = str(error)[:1000]
        log.insert(ignore_permissions=True)
        frappe.db.commit()
    except Exception:
        frappe.log_error(frappe.get_traceback(), "WhatsApp Log Insert Error")

def _send_to_bridge(send_url, bridge_token, tenant_id, payload, doc=None, to=None, text=None, has_media=False):
    import requests
    headers = {
        "Authorization": f"Bearer {bridge_token}",
        "Content-Type": "application/json",
        "X-Tenant": tenant_id
    }
    doctype_name = getattr(doc, "doctype", None)
    docname = getattr(doc, "name", None)

    _log_row(tenant_id, doctype_name, docname, to, text, has_media, status="Pending")

    try:
        r = requests.post(send_url, headers=headers, json=payload, timeout=30)
        if r.ok:
            data = r.json()
            corr = data.get("corr")
            results = data.get("results") or []
            ids = [x.get("id") for x in results if x.get("id")]
            _log_row(tenant_id, doctype_name, docname, to, text, has_media, status="Success", corr=corr, msg_ids=ids)
        else:
            _log_row(tenant_id, doctype_name, docname, to, text, has_media, status="Failed",
                     error=f"{r.status_code}: {r.text}")
            frappe.log_error(f"WA send failed {r.status_code}: {r.text}", "WhatsApp Bridge")
    except Exception:
        _log_row(tenant_id, doctype_name, docname, to, text, has_media, status="Failed",
                 error=frappe.get_traceback())
        frappe.log_error(frappe.get_traceback(), "WhatsApp Bridge Exception")

# Map Frappe doc_events -> Notification.event values
_EVENT_MAP = {
    "on_submit": "Submit",
    "on_cancel": "Cancel",
    "on_update": "Save",
    "after_insert": "New",
}

def handle_event(doc, method=None):
    """
    Generic dispatcher: for any doc event, find Notification rows that are enabled,
    match this doctype+event, and have the custom flag "Send via WhatsApp", then send.
    """
    try:
        event = _EVENT_MAP.get(method or "", None)
        if not event:
            return

        notif_names = frappe.get_all(
            "Notification",
            filters={
                "enabled": 1,
                "document_type": doc.doctype,
                "event": event,
                "send_via_whatsapp": 1,  # custom checkbox field
            },
            pluck="name"
        )
        if not notif_names:
            return

        send_url, bridge_token, tenant_id, default_country = _get_settings()
        if not (send_url and bridge_token and tenant_id):
            frappe.log_error("WhatsApp Bridge Settings incomplete", "WhatsApp Bridge")
            return

        for name in notif_names:
            n = frappe.get_doc("Notification", name)

            # Optional condition
            if n.condition:
                try:
                    if not frappe.safe_eval(n.condition, None, {"doc": doc}):
                        continue
                except Exception:
                    frappe.log_error(f"Invalid condition in Notification {n.name}", "WhatsApp Bridge")
                    continue

            # Resolve recipient(s)
            to_raw = None
            if getattr(n, "whatsapp_to_expr", None):
                try:
                    to_raw = _render_jinja(n.whatsapp_to_expr, doc).strip()
                except Exception:
                    frappe.log_error(f"Invalid WhatsApp To Jinja in Notification {n.name}", "WhatsApp Bridge")
            if not to_raw:
                to_raw = _find_mobile_default(doc)
            if not to_raw:
                frappe.log_error(f"No mobile found for {doc.doctype} {doc.name}", "WhatsApp Bridge")
                continue

            tos = [t.strip() for t in str(to_raw).replace(";", ",").split(",") if t.strip()]
            tos = [_normalize_msisdn(t, getattr(doc, "country", None) or default_country) for t in tos if t]

            # Render message
            try:
                text = _render_jinja(n.message or "", doc)
            except Exception:
                frappe.log_error(f"Invalid Notification.message Jinja in {n.name}", "WhatsApp Bridge")
                continue

            # Optional PDF
            b64 = None
            filename = None
            if getattr(n, "attach_print", 0):
                try:
                    b64 = _pdf_base64(doc.doctype, doc.name, getattr(n, "print_format", None))
                    filename = f"{doc.name}.pdf"
                except Exception:
                    frappe.log_error(
                        f"Failed to render PDF for {doc.doctype} {doc.name} (Notification {n.name})",
                        "WhatsApp Bridge"
                    )

            # Send to each recipient
            for to in tos:
                payload = {
                    "tenant": tenant_id,
                    "to": to,
                    "message": text or ""
                }
                has_media = False
                if b64:
                    payload["media"] = {
                        "items": [{
                            "base64": b64,
                            "mime": "application/pdf",
                            "filename": filename or f"{doc.name}.pdf",
                            "caption": f"{doc.doctype} {doc.name}"
                        }]
                    }
                    has_media = True

                _send_to_bridge(send_url, bridge_token, tenant_id, payload,
                                doc=doc, to=to, text=text, has_media=has_media)

    except Exception:
        frappe.log_error(frappe.get_traceback(), "WhatsApp Notification Dispatcher Error")

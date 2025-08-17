# Copyright (c) 2025, Flexcom Systems and contributors
# For license information, please see license.txt

import frappe, requests, json, base64
from frappe.model.document import Document

class WhatsAppBridgeSettings(Document):
    pass

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

# ---------- helpers ----------
def _get_settings():
    s = frappe.get_single("WhatsApp Bridge Settings")
    bridge_token = s.get_password(fieldname='bridge_token', raise_exception=False) if s.bridge_token else None
    return (
        (s.bridge_url or "").strip(),
        (bridge_token or "").strip(),
        (s.tenant_id or "").strip(),
        (s.default_country or "Nigeria").strip(),
    )

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

def _find_mobile(doc):
    for f in ("contact_mobile", "mobile_no", "phone"):
        v = getattr(doc, f, None)
        if v:
            return v
    if getattr(doc, "customer", None):
        m = frappe.db.get_value("Customer", doc.customer, "mobile_no")
        if m:
            return m
    return None

def _compose_text_for_si(doc):
    name = (
        getattr(doc, "customer_name", None)
        or (getattr(doc, "customer", None) and frappe.db.get_value("Customer", doc.customer, "customer_name"))
        or "Customer"
    )
    amount = getattr(doc, "rounded_total", 0) or getattr(doc, "grand_total", 0) or getattr(doc, "total", 0) or 0
    d = getattr(doc, "posting_date", None) or getattr(doc, "transaction_date", None) or ""
    if hasattr(d, "strftime"):
        d = d.strftime("%Y-%m-%d")
    return f"Hi {name}, your invoice {doc.name} is posted.\nAmount: {amount:,.2f}\nDate: {d}\nReply STOP to opt out."

def _pdf_base64_for_si(doc):
    pdf_bytes = frappe.get_print("Sales Invoice", doc.name, print_format=None, as_pdf=True)
    return base64.b64encode(pdf_bytes).decode("utf-8")

def _send(bridge_url, bridge_token, tenant_id, payload, doc=None, to=None, text=None, has_media=False):
    headers = {
        "Authorization": f"Bearer {bridge_token}",
        "Content-Type": "application/json",
        "X-Tenant": tenant_id
    }
    doctype_name = getattr(doc, "doctype", None)
    docname = getattr(doc, "name", None)

    # Pre-log (optional)
    _log_whatsapp_row(tenant_id, doctype_name, docname, to, text, has_media, status="Pending")

    try:
        r = requests.post(bridge_url, headers=headers, data=json.dumps(payload), timeout=25)
        if r.ok:
            data = r.json()
            corr = data.get("corr")
            results = data.get("results") or []
            ids = [x.get("id") for x in results if x.get("id")]
            _log_whatsapp_row(tenant_id, doctype_name, docname, to, text, has_media, status="Success", corr=corr, msg_ids=ids)
        else:
            _log_whatsapp_row(tenant_id, doctype_name, docname, to, text, has_media, status="Failed", error=f"{r.status_code}: {r.text}")
            frappe.log_error(f"WA send failed {r.status_code}: {r.text}", "WhatsApp Bridge")
    except Exception as e:
        _log_whatsapp_row(tenant_id, doctype_name, docname, to, text, has_media, status="Failed", error=str(e))
        frappe.log_error(frappe.get_traceback(), "WhatsApp Bridge Exception")


# ---------- hook target (called by hooks.py) ----------
def on_submit_sales_invoice(doc, method=None):
	"""
	Hook entrypoint for Sales Invoice on_submit.
	This is called with (doc, method) by Frappe's doc_events.
	"""
	bridge_url, bridge_token, tenant_id, default_country = _get_settings()
	if not (bridge_url and bridge_token and tenant_id):
		frappe.log_error("WhatsApp Bridge Settings incomplete", "WhatsApp Bridge")
		return

	mobile_raw = _find_mobile(doc)
	if not mobile_raw:
		frappe.log_error(f"No mobile found for {doc.doctype} {doc.name}", "WhatsApp Bridge")
		return

	country = (
		(getattr(doc, "customer_address", None) and frappe.db.get_value("Address", doc.customer_address, "country"))
		or getattr(doc, "country", None)
		or default_country
	)

	to = _normalize_msisdn(mobile_raw, country=country)
	if not to:
		frappe.log_error(f"Failed to normalize mobile for {doc.doctype} {doc.name}", "WhatsApp Bridge")
		return

	text = _compose_text_for_si(doc)
	pdfb64 = _pdf_base64_for_si(doc)
	filename = f"{doc.name}.pdf"

	payload = {
		"tenant": tenant_id,
		"to": to,
		"message": text,
		"media": {
			"items": [
				{
					"base64": pdfb64,
					"mime": "application/pdf",
					"filename": filename,
					"caption": f"Invoice {doc.name}"
				}
			]
		}
	}
	_send(bridge_url, bridge_token, tenant_id, payload, doc=doc, to=to, text=text, has_media=True)

def _log_whatsapp_row(tenant_id, doctype_name, docname, to, message, has_media, status, corr=None, msg_ids=None, error=None):
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

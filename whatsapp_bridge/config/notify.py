# whatsapp_bridge/notification_dispatcher.py

import json
import base64
import time
import random
import frappe
from frappe.utils.safe_exec import get_safe_globals

# -------------------- settings helpers --------------------
def _get_settings():
    s = frappe.get_single("WhatsApp Bridge Settings")
    bridge_token = s.get_password(fieldname='bridge_token', raise_exception=False) if s.bridge_token else None
    url = (s.bridge_url or "").strip()
    token = (bridge_token or "").strip()
    tenant = (s.tenant_id or "").strip()
    country = (s.default_country or "Nigeria").strip()
    return (url, token, tenant, country)

def _fmt_money(v, currency=None, precision=None):
    try:
        return frappe.utils.fmt_money(v or 0, currency=currency, precision=precision)
    except Exception:
        try:
            return f"{float(v or 0):,.2f}"
        except Exception:
            return str(v or 0)

def _render_jinja(tpl, doc):
    if not tpl:
        return ""
    ctx = {"doc": doc, "fmt_money": _fmt_money}
    ctx.update(get_safe_globals())
    return frappe.render_template(tpl, ctx)

# -------------------- phone utilities --------------------
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

def _split_numbers(value):
    return [p.strip() for p in str(value).replace(";", ",").split(",") if p and p.strip()]

# -------------------- recipient helpers --------------------
def _dedupe_keep_order(seq):
    seen, out = set(), []
    for x in seq:
        if x and x not in seen:
            out.append(x)
            seen.add(x)
    return out

def _numbers_from_string(value, country, doc_country=None):
    nums = []
    for token in _split_numbers(value):
        n = _normalize_msisdn(token, doc_country or country)
        if n:
            nums.append(n)
    return nums

def _numbers_from_user(user_id, country, doc_country=None):
    if not user_id:
        return []
    mobile = frappe.db.get_value("User", user_id, "mobile_no")
    return _numbers_from_string(mobile or "", country, doc_country)

def _numbers_from_contact(contact_name, country, doc_country=None):
    if not contact_name:
        return []
    mobile, phone = frappe.db.get_value("Contact", contact_name, ["mobile_no", "phone"])
    collected = []
    if mobile or phone:
        collected.extend(_numbers_from_string(mobile or phone or "", country, doc_country))
    else:
        rows = frappe.get_all(
            "Contact Phone",
            filters={"parenttype": "Contact", "parent": contact_name},
            fields=["phone", "is_primary_mobile", "is_primary_phone", "idx"],
            order_by="is_primary_mobile desc, is_primary_phone desc, idx asc",
            limit=10,
        )
        for r in rows:
            collected.extend(_numbers_from_string(r.get("phone") or "", country, doc_country))
    return collected

def _looks_phone_field(df):
    label = (df.label or "").lower()
    fname = (df.fieldname or "").lower()
    return (
        df.fieldtype in ("Phone", "Data", "Small Text")
        and (
            "phone" in label or "mobile" in label or "whatsapp" in label
            or "phone" in fname or "mobile" in fname or "whatsapp" in fname
        )
    )

def _extract_from_child_rows(child_rows, country, doc_country=None):
    out = []
    if not child_rows:
        return out
    for row in child_rows:
        try:
            doctype = row.doctype if hasattr(row, "doctype") else row.get("doctype")
            meta = frappe.get_meta(doctype) if doctype else None
        except Exception:
            meta = None
        if not meta:
            for k, v in (row.items() if isinstance(row, dict) else []):
                if any(x in str(k).lower() for x in ("phone", "mobile", "whatsapp")) and v:
                    out.extend(_numbers_from_string(v, country, doc_country))
            continue
        for df in (meta.fields or []):
            if _looks_phone_field(df):
                val = row.get(df.fieldname) if isinstance(row, dict) else getattr(row, df.fieldname, None)
                if val:
                    out.extend(_numbers_from_string(val, country, doc_country))
    return out

def _numbers_from_doc_field(doc, fieldname, country):
    if not (doc and fieldname):
        return []
    df = frappe.get_meta(doc.doctype).get_field(fieldname)
    if not df:
        return []
    value = doc.get(fieldname)
    if not value:
        return []
    doc_country = getattr(doc, "country", None)

    if df.fieldtype in ("Phone", "Data", "Small Text"):
        return _numbers_from_string(value, country, doc_country)

    if df.fieldtype == "Link":
        target = (df.options or "").strip()
        if target == "User":
            return _numbers_from_user(value, country, doc_country)
        if target == "Contact":
            return _numbers_from_contact(value, country, doc_country)
        try:
            ldoc = frappe.get_doc(target, value)
            for guess in ("mobile_no", "phone", "contact_mobile"):
                if ldoc.get(guess):
                    return _numbers_from_string(ldoc.get(guess), country, doc_country)
            meta = frappe.get_meta(ldoc.doctype)
            collected = []
            for f in (meta.fields or []):
                if _looks_phone_field(f) and ldoc.get(f.fieldname):
                    collected.extend(_numbers_from_string(ldoc.get(f.fieldname), country, doc_country))
            return collected
        except Exception:
            return []

    if df.fieldtype == "Table":
        return _extract_from_child_rows(value, country, doc_country)

    if df.fieldtype == "Dynamic Link":
        target_doctype = doc.get(df.options)
        target_name = value
        if target_doctype and target_name:
            try:
                ldoc = frappe.get_doc(target_doctype, target_name)
                for guess in ("mobile_no", "phone", "contact_mobile"):
                    if ldoc.get(guess):
                        return _numbers_from_string(ldoc.get(guess), country, doc_country)
                meta = frappe.get_meta(ldoc.doctype)
                collected = []
                for f in (meta.fields or []):
                    if _looks_phone_field(f) and ldoc.get(f.fieldname):
                        collected.extend(_numbers_from_string(ldoc.get(f.fieldname), country, doc_country))
                return collected
            except Exception:
                return []

    return []

# -------------------- rate limiting (per-tenant) --------------------
def _rate_limit_wait(tenant_id, min_interval=1.5, max_per_min=20):
    """
    Gentle throttling to avoid Meta rate flags.
    - Enforce a minimum interval between sends per tenant.
    - Cap burst to `max_per_min` per 60s; if exceeded, sleep until safe.
    Uses frappe.cache() (Redis) to coordinate across workers.
    """
    try:
        cache = frappe.cache()
        now = time.time()
        jitter = random.uniform(0.05, 0.25)

        # 1) min interval
        last_key = f"wa_last_send::{tenant_id}"
        last = cache.get_value(last_key)
        if last:
            try:
                last = float(last)
                wait = (min_interval - (now - last))
                if wait > 0:
                    time.sleep(min(wait + jitter, 5.0))
            except Exception:
                pass

        # 2) per-minute cap (sliding window)
        win_key = f"wa_minute_win::{tenant_id}"
        raw = cache.get_value(win_key) or "[]"
        try:
            import json as _json
            hist = [t for t in _json.loads(raw) if (now - float(t)) < 60.0]
        except Exception:
            hist = []

        if len(hist) >= max_per_min:
            earliest = min(hist)
            sleep_for = max(0.0, 60.0 - (now - earliest)) + jitter
            time.sleep(min(sleep_for, 10.0))
            now = time.time()
            hist = [t for t in hist if (now - float(t)) < 60.0]

        # record this attempt
        hist.append(now)
        try:
            import json as _json
            cache.set_value(win_key, _json.dumps(hist[-max_per_min:]))
        except Exception:
            pass

        cache.set_value(last_key, str(now))
    except Exception:
        # Never let rate-limiter break the workflow
        pass

# -------------------- logging (single row, update later) --------------------
def _create_log(tenant_id, doctype_name, docname, to, message, has_media, status="Pending"):
    """
    Create ONE row (Pending) and return its name; caller updates it later.
    """
    try:
        log = frappe.new_doc("WhatsApp Message Log")
        log.tenant_id = tenant_id
        log.doctype_name = doctype_name
        log.docname = docname
        log.to_number = to
        log.message_preview = (message or "")[:500]
        log.has_media = 1 if has_media else 0
        log.status = status
        log.sent_on = frappe.utils.now_datetime()
        log.insert(ignore_permissions=True)
        frappe.db.commit()
        return log.name
    except Exception:
        frappe.log_error(frappe.get_traceback(), "WhatsApp Log Insert Error")
        return None

def _update_log(name, **fields):
    if not name:
        return
    try:
        if "msg_ids" in fields:
            fields["bridge_msg_ids"] = frappe.as_json(fields.pop("msg_ids") or [])
        if "corr" in fields:
            fields["bridge_corr_id"] = fields.pop("corr") or ""
        frappe.db.set_value("WhatsApp Message Log", name, fields)
        frappe.db.commit()
    except Exception:
        frappe.log_error(frappe.get_traceback(), "WhatsApp Log Update Error")

# -------------------- bridge call --------------------
def _send_to_bridge(send_url, bridge_token, tenant_id, payload, *, log_name=None, doc=None, to=None, text=None, has_media=False):
    import requests
    headers = {
        "Authorization": f"Bearer {bridge_token}",
        "Content-Type": "application/json",
        "X-Tenant": tenant_id
    }

    # Throttle per tenant before sending
    _rate_limit_wait(tenant_id)

    try:
        r = requests.post(send_url, headers=headers, data=json.dumps(payload), timeout=25)
        if r.ok:
            data = r.json()
            corr = data.get("corr")
            results = data.get("results") or []
            ids = [x.get("id") for x in results if x.get("id")]
            _update_log(log_name, status="Success", corr=corr, msg_ids=ids, error="")
        else:
            _update_log(log_name, status="Failed", error=f"{r.status_code}: {r.text}")
            frappe.log_error(f"WA send failed {r.status_code}: {r.text}", "WhatsApp Bridge")
    except Exception:
        err = frappe.get_traceback()
        _update_log(log_name, status="Failed", error=err)
        frappe.log_error(err, "WhatsApp Bridge Exception")

# -------------------- main event dispatcher --------------------
_EVENT_MAP = {
    "on_submit": "Submit",
    "on_cancel": "Cancel",
    "on_update": "Save",
    "after_insert": "New",
}

def handle_event(doc, method=None):
    """
    If Notification.channel == 'WhatsApp Bridge' for this doctype & event,
    render message, resolve recipients (Recipients grid first), attach PDF if selected,
    and send via the bridge.

    For each recipient:
      - Create ONE log row with status 'Pending' and message preview
      - Send (with throttling)
      - Update that same row to 'Success' or 'Failed'
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
                "channel": "WhatsApp Bridge",
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
                    ok = frappe.safe_eval(n.condition, None, {"doc": doc})
                    if not ok:
                        continue
                except Exception:
                    frappe.log_error(f"Invalid condition in Notification {n.name}", "WhatsApp Bridge")
                    continue

            tos = _numbers_from_recipients(n, doc, default_country)
            if not tos:
                frappe.log_error(f"No mobile recipients for {doc.doctype} {doc.name}", "WhatsApp Bridge")
                continue

            # Render message once
            text = _render_jinja(n.message or "", doc)

            # Optional PDF
            b64 = None
            filename = None
            if getattr(n, "attach_print", 0):
                try:
                    b64 = _pdf_base64(doc.doctype, doc.name, n.print_format)
                    filename = f"{doc.name}.pdf"
                except Exception:
                    frappe.log_error(
                        f"Failed to render PDF for {doc.doctype} {doc.name} (Notification {n.name})",
                        "WhatsApp Bridge"
                    )

            # Send per recipient (one log row each)
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

                # Create a single Pending log with preview, then update later
                log_name = _create_log(
                    tenant_id=tenant_id,
                    doctype_name=getattr(doc, "doctype", None),
                    docname=getattr(doc, "name", None),
                    to=to,
                    message=(text or f"{doc.doctype} {doc.name}"),
                    has_media=has_media,
                    status="Pending",
                )

                _send_to_bridge(
                    send_url, bridge_token, tenant_id, payload,
                    log_name=log_name, doc=doc, to=to, text=text, has_media=has_media
                )

    except Exception:
        frappe.log_error(frappe.get_traceback(), "WhatsApp Notification Dispatcher Error")

def _numbers_from_recipients(notification_doc, doc, default_country):
    out = []
    rows = (getattr(notification_doc, "recipients", None) or [])

    for r in rows:
        fieldname = (getattr(r, "receiver_by_document_field", "") or "").strip()
        if fieldname:
            out.extend(_numbers_from_doc_field(doc, fieldname, default_country))

        role = (getattr(r, "receiver_by_role", "") or "").strip()
        if role:
            users = frappe.get_all("Has Role", filters={"role": role}, fields=["parent"])
            for u in users:
                out.extend(_numbers_from_user(u.parent, default_country, getattr(doc, "country", None)))

        explicit_user = (getattr(r, "receiver_by_user", "") or "").strip()
        if explicit_user:
            out.extend(_numbers_from_user(explicit_user, default_country, getattr(doc, "country", None)))

        user_field = (getattr(r, "receiver_by_user_field", "") or "").strip()
        if user_field and doc.get(user_field):
            out.extend(_numbers_from_user(doc.get(user_field), default_country, getattr(doc, "country", None)))

    if not out:
        for guess in ("contact_mobile", "mobile_no", "phone"):
            if doc.get(guess):
                out.extend(_numbers_from_string(doc.get(guess), default_country, getattr(doc, "country", None)))
                break

    return _dedupe_keep_order(out)

# -------------------- pdf helper --------------------
def _pdf_base64(dt, name, print_format=None):
    pdf_bytes = frappe.get_print(dt, name, print_format=print_format, as_pdf=True)
    return base64.b64encode(pdf_bytes).decode("utf-8")

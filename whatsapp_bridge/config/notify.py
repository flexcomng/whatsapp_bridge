# whatsapp_bridge/notification_dispatcher.py

import json
import base64
import frappe
from frappe.utils.safe_exec import get_safe_globals

# -------------------- debug helpers --------------------
def _debug_enabled():
    try:
        # Manual override in-process
        if getattr(frappe.flags, "wa_debug", None) is not None:
            return bool(frappe.flags.wa_debug)
        s = frappe.get_single("WhatsApp Bridge Settings")
        return bool(getattr(s, "debug", 0) or getattr(s, "debug_log", 0) or frappe.conf.get("developer_mode"))
    except Exception:
        return bool(frappe.conf.get("developer_mode"))

def _dbg(msg, **kw):
    if not _debug_enabled():
        return
    try:
        line = f"[WA] {msg}"
        if kw:
            try:
                line += " | " + frappe.as_json(kw, indent=None)
            except Exception:
                line += f" | {kw}"
        # logger
        try:
            frappe.logger("whatsapp_bridge").info(line)
        except Exception:
            pass
        # stdout (visible in bench logs)
        print(line)
    except Exception:
        pass

def _short(s, n=200):
    try:
        ss = str(s)
        return ss if len(ss) <= n else ss[: n - 3] + "..."
    except Exception:
        return s

# -------------------- settings helpers --------------------
def _get_settings():
    s = frappe.get_single("WhatsApp Bridge Settings")
    bridge_token = s.get_password(fieldname='bridge_token', raise_exception=False) if s.bridge_token else None
    url = (s.bridge_url or "").strip()
    token = (bridge_token or "").strip()
    tenant = (s.tenant_id or "").strip()
    country = (s.default_country or "Nigeria").strip()
    _dbg("loaded_settings", bridge_url=bool(url), has_token=bool(token), tenant_id=_short(tenant, 40), default_country=country)
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
    rendered = frappe.render_template(tpl, ctx)
    _dbg("rendered_message", length=len(rendered))
    return rendered

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
    _dbg("numbers_from_string", raw=_short(value), resolved=nums)
    return nums

def _numbers_from_user(user_id, country, doc_country=None):
    if not user_id:
        return []
    mobile = frappe.db.get_value("User", user_id, "mobile_no")
    nums = _numbers_from_string(mobile or "", country, doc_country)
    _dbg("numbers_from_user", user=user_id, found=nums)
    return nums

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
    _dbg("numbers_from_contact", contact=contact_name, found=collected)
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
    _dbg("extract_from_child_rows", rows=len(child_rows), found=out)
    return out

def _numbers_from_doc_field(doc, fieldname, country):
    if not (doc and fieldname):
        return []
    df = frappe.get_meta(doc.doctype).get_field(fieldname)
    if not df:
        _dbg("doc_field_missing", doctype=doc.doctype, field=fieldname)
        return []
    value = doc.get(fieldname)
    if not value:
        _dbg("doc_field_empty", doctype=doc.doctype, field=fieldname)
        return []
    doc_country = getattr(doc, "country", None)
    _dbg("doc_field_resolve_start", doctype=doc.doctype, field=fieldname, fieldtype=df.fieldtype, options=getattr(df, "options", None))

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
                    nums = _numbers_from_string(ldoc.get(guess), country, doc_country)
                    _dbg("doc_field_link_guess_hit", target=target, guess=guess, found=nums)
                    return nums
            meta = frappe.get_meta(ldoc.doctype)
            collected = []
            for f in (meta.fields or []):
                if _looks_phone_field(f) and ldoc.get(f.fieldname):
                    collected.extend(_numbers_from_string(ldoc.get(f.fieldname), country, doc_country))
            _dbg("doc_field_link_scanned", target=target, found=collected)
            return collected
        except Exception as e:
            _dbg("doc_field_link_error", field=fieldname, error=str(e))
            return []

    if df.fieldtype == "Table":
        nums = _extract_from_child_rows(value, country, doc_country)
        return nums

    if df.fieldtype == "Dynamic Link":
        target_doctype = doc.get(df.options)
        target_name = value
        if target_doctype and target_name:
            try:
                ldoc = frappe.get_doc(target_doctype, target_name)
                for guess in ("mobile_no", "phone", "contact_mobile"):
                    if ldoc.get(guess):
                        nums = _numbers_from_string(ldoc.get(guess), country, doc_country)
                        _dbg("doc_field_dynamic_link_guess_hit", target=target_doctype, guess=guess, found=nums)
                        return nums
                meta = frappe.get_meta(ldoc.doctype)
                collected = []
                for f in (meta.fields or []):
                    if _looks_phone_field(f) and ldoc.get(f.fieldname):
                        collected.extend(_numbers_from_string(ldoc.get(f.fieldname), country, doc_country))
                _dbg("doc_field_dynamic_link_scanned", target=target_doctype, found=collected)
                return collected
            except Exception as e:
                _dbg("doc_field_dynamic_link_error", field=fieldname, error=str(e))
                return []

    _dbg("doc_field_unhandled_type", field=fieldname, fieldtype=df.fieldtype)
    return []

# -------------------- recipients resolution (enhanced) --------------------
def _numbers_from_recipients(notification_doc, doc, default_country):
    out = []
    rows = (getattr(notification_doc, "recipients", None) or [])
    _dbg("recipients_rows", count=len(rows))

    for idx, r in enumerate(rows, start=1):
        _dbg("recipients_row_start", row=idx)

        fieldname = (getattr(r, "receiver_by_document_field", "") or "").strip()
        if fieldname:
            nums = _numbers_from_doc_field(doc, fieldname, default_country)
            _dbg("recipients_row_doc_field", row=idx, field=fieldname, found=nums)
            out.extend(nums)

        role = (getattr(r, "receiver_by_role", "") or "").strip()
        if role:
            users = frappe.get_all("Has Role", filters={"role": role}, fields=["parent"])
            _dbg("recipients_row_role", row=idx, role=role, user_count=len(users))
            for u in users:
                out.extend(_numbers_from_user(u.parent, default_country, getattr(doc, "country", None)))

        explicit_user = (getattr(r, "receiver_by_user", "") or "").strip()
        if explicit_user:
            nums = _numbers_from_user(explicit_user, default_country, getattr(doc, "country", None))
            _dbg("recipients_row_explicit_user", row=idx, user=explicit_user, found=nums)
            out.extend(nums)

        user_field = (getattr(r, "receiver_by_user_field", "") or "").strip()
        if user_field and doc.get(user_field):
            nums = _numbers_from_user(doc.get(user_field), default_country, getattr(doc, "country", None))
            _dbg("recipients_row_user_field", row=idx, user_field=user_field, user=doc.get(user_field), found=nums)
            out.extend(nums)

    if not out:
        for guess in ("contact_mobile", "mobile_no", "phone"):
            if doc.get(guess):
                nums = _numbers_from_string(doc.get(guess), default_country, getattr(doc, "country", None))
                _dbg("recipients_fallback_doc_fields", field=guess, found=nums)
                out.extend(nums)
                break

    out = _dedupe_keep_order(out)
    _dbg("recipients_final", numbers=out)
    return out

# -------------------- pdf helper --------------------
def _pdf_base64(dt, name, print_format=None):
    pdf_bytes = frappe.get_print(dt, name, print_format=print_format, as_pdf=True)
    _dbg("pdf_generated", doctype=dt, name=name, bytes=len(pdf_bytes))
    return base64.b64encode(pdf_bytes).decode("utf-8")

# -------------------- logging --------------------
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
        log.status = status
        log.bridge_corr_id = corr or ""
        log.bridge_msg_ids = frappe.as_json(msg_ids or [])
        log.sent_on = frappe.utils.now_datetime()
        if error:
            log.error = str(error)[:1000]
        log.insert(ignore_permissions=True)
        frappe.db.commit()
    except Exception:
        frappe.log_error(frappe.get_traceback(), "WhatsApp Log Insert Error")

# -------------------- bridge call --------------------
def _send_to_bridge(send_url, bridge_token, tenant_id, payload, doc=None, to=None, text=None, has_media=False):
    import requests
    headers = {
        "Authorization": f"Bearer {bridge_token}",
        "Content-Type": "application/json",
        "X-Tenant": tenant_id
    }
    doctype_name = getattr(doc, "doctype", None)
    docname = getattr(doc, "name", None)

    _dbg("bridge_request", to=to, has_media=has_media, keys=list(payload.keys()))
    _log_row(tenant_id, doctype_name, docname, to, text, has_media, status="Pending")

    try:
        r = requests.post(send_url, headers=headers, data=json.dumps(payload), timeout=25)
        if r.ok:
            data = r.json()
            corr = data.get("corr")
            results = data.get("results") or []
            ids = [x.get("id") for x in results if x.get("id")]
            _dbg("bridge_response_ok", corr=corr, ids=ids)
            _log_row(tenant_id, doctype_name, docname, to, text, has_media, status="Success", corr=corr, msg_ids=ids)
        else:
            _dbg("bridge_response_error", status=r.status_code, text=_short(r.text, 500))
            _log_row(tenant_id, doctype_name, docname, to, text, has_media, status="Failed", error=f"{r.status_code}: {r.text}")
            frappe.log_error(f"WA send failed {r.status_code}: {r.text}", "WhatsApp Bridge")
    except Exception:
        _dbg("bridge_exception", error=_short(frappe.get_traceback(), 500))
        _log_row(tenant_id, doctype_name, docname, to, text, has_media, status="Failed", error=frappe.get_traceback())
        frappe.log_error(frappe.get_traceback(), "WhatsApp Bridge Exception")

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
    """
    try:
        event = _EVENT_MAP.get(method or "", None)
        _dbg("handle_event_start", method=method, mapped_event=event, doctype=doc.doctype, name=doc.name)
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
        _dbg("notifications_matched", count=len(notif_names), names=notif_names)
        if not notif_names:
            return

        send_url, bridge_token, tenant_id, default_country = _get_settings()
        if not (send_url and bridge_token and tenant_id):
            frappe.log_error("WhatsApp Bridge Settings incomplete", "WhatsApp Bridge")
            _dbg("settings_incomplete")
            return

        for name in notif_names:
            n = frappe.get_doc("Notification", name)
            _dbg("process_notification", notification=name)

            # Optional condition
            if n.condition:
                try:
                    ok = frappe.safe_eval(n.condition, None, {"doc": doc})
                    _dbg("condition_eval", ok=bool(ok), condition=_short(n.condition, 200))
                    if not ok:
                        continue
                except Exception as e:
                    frappe.log_error(f"Invalid condition in Notification {n.name}", "WhatsApp Bridge")
                    _dbg("condition_error", error=str(e))
                    continue

            tos = _numbers_from_recipients(n, doc, default_country)
            if not tos:
                frappe.log_error(f"No mobile recipients for {doc.doctype} {doc.name}", "WhatsApp Bridge")
                _dbg("no_recipients", doctype=doc.doctype, name=doc.name)
                continue

            text = _render_jinja(n.message or "", doc)

            b64 = None
            filename = None
            if getattr(n, "attach_print", 0):
                try:
                    b64 = _pdf_base64(doc.doctype, doc.name, n.print_format)
                    filename = f"{doc.name}.pdf"
                except Exception as e:
                    frappe.log_error(
                        f"Failed to render PDF for {doc.doctype} {doc.name} (Notification {n.name})",
                        "WhatsApp Bridge"
                    )
                    _dbg("pdf_error", error=str(e))

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
        _dbg("dispatcher_exception", error=_short(frappe.get_traceback(), 500))

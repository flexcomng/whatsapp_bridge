import frappe
from frappe.email.doctype.notification.notification import Notification as BaseNotification
from frappe.utils import get_url
from frappe.integrations.utils import make_post_request

def _get_settings():
    s = frappe.get_single("WhatsApp Bridge Settings")
    token = s.get_password("bridge_token") if s.bridge_token else None
    return (
        (s.bridge_url or "").strip(),           # e.g. http://127.0.0.1:3001/send
        (token or "").strip(),
        (s.default_country or "Nigeria").strip(),
    )

class WANotification(BaseNotification):
    """Extend core Notification to support channel = 'WhatsApp Bridge'."""

    def send(self, doc):
        if self.channel == "WhatsApp Bridge":
            return self.send_whatsapp(doc)
        # fall back to the stock behavior for other channels
        return super().send(doc)

    # --- WhatsApp Bridge implementation ---
    def send_whatsapp(self, doc):
        # Build message body using same context rendering as email notifications
        context = self.get_context(doc)
        body = frappe.render_template(self.message or "", context)

        # Collect recipient phone fields from the Recipients grid (same idea as SMS)
        numbers = self._collect_numbers_from_recipients(doc)
        if not numbers:
            frappe.throw("No WhatsApp recipients found. Set them in Recipients → Receiver By Document Field.")

        # Optional: attach print as PDF (same semantics as Email channel)
        attachments = []
        if self.attach_print:
            pdf = frappe.get_print(
                self.document_type,
                doc.name,
                self.print_format or None,
                as_pdf=True,
                letterhead=self.letterhead or None,
            )
            fname = f"{self.document_type}-{doc.name}.pdf"
            fdoc = frappe.get_doc({
                "doctype": "File",
                "file_name": fname,
                "is_private": 1,
                "content": pdf,
            }).insert(ignore_permissions=True)
            attachments.append({
                "url": get_url(fdoc.file_url),
                "filename": fname,
                "mime_type": "application/pdf",
            })

        url, token, _default_country = _get_settings()
        if not url:
            frappe.throw("WhatsApp Bridge Settings: Bridge URL is not set.")

        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        # Send one message per recipient (adjust if your bridge supports bulk)
        for to in numbers:
            payload = {
                "to": to,  # number must be in your bridge’s expected format
                "text": body,
            }
            if attachments:
                payload["attachments"] = attachments

            # Uses Frappe’s HTTP helper (no raw requests)
            make_post_request(url=url, headers=headers, data=payload)

    def _collect_numbers_from_recipients(self, doc):
        """Mirror SMS behavior: pull values from Receiver By Document Field rows."""
        out = []
        for row in (self.recipients or []):
            fieldname = (row.receiver_by_document_field or "").strip()
            if not fieldname:
                continue
            val = (doc.get(fieldname) or "").strip()
            if val:
                out.append(val)
        # de-dup while keeping order
        seen, unique = set(), []
        for v in out:
            if v not in seen:
                seen.add(v)
                unique.append(v)
        return unique

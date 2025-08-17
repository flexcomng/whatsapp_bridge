import frappe
from frappe.custom.doctype.property_setter.property_setter import make_property_setter

def execute():
    # 0) Remove any WRONG DocType-level property setter for Notification.options
    frappe.db.delete("Property Setter", {
        "doc_type": "Notification",
        "property": "options",
        "doctype_or_field": "DocType",
    })

    # 1) Read current field options from the DocField
    df = frappe.get_meta("Notification").get_field("channel")
    current = [o.strip() for o in (df.options or "").splitlines() if o.strip()]

    # 2) Append our option if missing
    if "WhatsApp Bridge" not in current:
        current.append("WhatsApp Bridge")
    new_opts = "\n".join(current)

    # 3) Upsert a DocField-level Property Setter for channel.options
    existing = frappe.db.get_value(
        "Property Setter",
        {
            "doc_type": "Notification",
            "doctype_or_field": "DocField",
            "field_name": "channel",
            "property": "options",
        },
        "name",
    )

    if existing:
        ps = frappe.get_doc("Property Setter", existing)
        ps.value = new_opts
        ps.property_type = "Text"  # IMPORTANT: options is Text, not Select
        ps.save(ignore_permissions=True)
    else:
        make_property_setter(
            doctype="Notification",
            fieldname="channel",
            property="options",
            value=new_opts,
            property_type="Text",
        )

    # 4) Reload + clear cache so validation sees the new options
    frappe.reload_doctype("Notification")
    frappe.clear_cache(doctype="Notification")

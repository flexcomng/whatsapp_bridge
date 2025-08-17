frappe.ui.form.on('Notification', {
  setup(frm) {
    ensure_whatsapp_channel(frm);
  },
  refresh(frm) {
    ensure_whatsapp_channel(frm);
    show_wa_hint(frm);
    maybe_set_recipient_field_options(frm);
  },
  channel(frm) {
    show_wa_hint(frm);
    maybe_set_recipient_field_options(frm);
  },
  document_type(frm) {
    maybe_set_recipient_field_options(frm);
  }
});

function ensure_whatsapp_channel(frm) {
  const field = frm.get_field('channel');
  if (!field) return;

  const raw = (field.df.options || '').split('\n').map(s => s.trim()).filter(Boolean);
  if (!raw.includes('WhatsApp Bridge')) {
    raw.push('WhatsApp Bridge');
    field.df.options = raw.join('\n');
    field.refresh();
  }
}

function is_whatsapp(frm) {
  return (frm.doc.channel || '') === 'WhatsApp Bridge';
}

function show_wa_hint(frm) {
  if (!is_whatsapp(frm)) {
    frm.clear_custom_banner && frm.clear_custom_banner();
    return;
  }
  const msg = 'WhatsApp Bridge: uses Message, Attach Print, and document-field recipients. ' +
              'Pick the mobile/phone field from your document in the Recipients grid.';
  if (frm.show_custom_banner) {
    frm.show_custom_banner(msg, 'blue');
  } else {
    frappe.show_alert({ message: msg, indicator: 'blue' }, 5);
  }
}

/**
 * Populate Recipients → Receiver By Document Field with likely phone/mobile fields
 * from the selected Document Type when channel is WhatsApp Bridge.
 */
function maybe_set_recipient_field_options(frm) {
  if (!is_whatsapp(frm) || !frm.doc.document_type) return;

  frappe.model.with_doctype(frm.doc.document_type, () => {
    const meta = frappe.get_meta(frm.doc.document_type);
    const options = [];

    (meta.fields || []).forEach(df => {
      const fname = (df.fieldname || '').toLowerCase();
      const flabel = (df.label || '').toLowerCase();

      // Strong candidates:
      // - fieldtype Phone (v15)
      // - Data field with options "Phone"
      // - Anything that looks like a phone/mobile by name/label
      const looks_phone = fname.includes('mobile') || fname.includes('phone') || flabel.includes('mobile') || flabel.includes('phone');
      if (
        df.fieldtype === 'Phone' ||
        (df.fieldtype === 'Data' && (df.options === 'Phone' || looks_phone)) ||
        (looks_phone && (df.fieldtype === 'Data' || df.fieldtype === 'Small Text'))
      ) {
        options.push(`${df.fieldname}`);
      }
    });

    // Fall back to all Data/Phone fields if nothing matched the heuristic
    if (!options.length) {
      (meta.fields || []).forEach(df => {
        if (df.fieldtype === 'Phone' || df.fieldtype === 'Data') {
          options.push(`${df.fieldname}`);
        }
      });
    }

    // Update the child table column options
    const grid = frm.fields_dict.recipients && frm.fields_dict.recipients.grid;
    if (grid) {
      grid.update_docfield_property(
        'receiver_by_document_field',
        'options',
        options.join('\n')
      );
      frm.refresh_field('recipients');
    }
  });
}

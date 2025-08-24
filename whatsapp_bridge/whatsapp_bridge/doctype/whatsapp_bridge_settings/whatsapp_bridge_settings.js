// Copyright (c) 2025, Flexcom Systems and contributors
// For license information, please see license.txt

frappe.ui.form.on('WhatsApp Bridge Settings', {
  refresh(frm) {
    frm.add_custom_button('Show Status', async () => {
      try {
        const r = await frappe.call({ method: 'whatsapp_bridge.api.api.bridge_status' });
        const d = r.message || {};
        frappe.msgprint(__('Running: {0}<br>{1}', [d.running ? 'Yes' : 'No', frappe.utils.escape_html(d.message || '')]));
      } catch {
        frappe.msgprint(__('Status check failed'));
      }
    });
    if (!frm.is_new()) {
      frm.add_custom_button('Restart Bridge', async () => {
        try {
          await frappe.call({ method: 'whatsapp_bridge.after_install.restart_compose' });
          frappe.show_alert({ message: 'Bridge restarted', indicator: 'green' });
        } catch (e) {
          frappe.msgprint(__('Failed to restart bridge: {0}', [e.message || e]));
        }
      }).addClass('btn-primary');
    }
    frm.add_custom_button('Rotate Token', async () => {
      try {
        const r = await frappe.call({ method: 'whatsapp_bridge.api.api.rotate_token' });
        if (r.message && r.message.ok) {
          frm.reload_doc();
          frappe.msgprint(__('Token rotated and bridge restarted.'));
        }
      } catch {
        frappe.msgprint(__('Rotation failed'));
      }
    });

    frm.add_custom_button('Open QR', async () => {
      const tenant = frm.doc.tenant_id || '';
      if (!tenant) return frappe.msgprint('Set Tenant ID first.');

      try {
        const r = await frappe.call({ doc: frm.doc, method: 'get_token' });
        const token = r.message;
        if (!token) return frappe.msgprint('Could not fetch token.');

        const host = window.location.hostname;
        const url  = `https://${host}:3001/qr?tenant=${encodeURIComponent(tenant)}&token=${encodeURIComponent(token)}`;
        window.open(url, '_blank', 'noopener');
      } catch (e) {
        frappe.msgprint(__('Failed to fetch token: {0}', [e.message || e]));
      }
    });
    // Re-init (wipe) and open QR (no index.js changes needed)
    frm.add_custom_button('Re-init (wipe) + Open QR', async () => {
      const tenant = frm.doc.tenant_id || '';
      if (!tenant) return frappe.msgprint(__('Set Tenant ID first.'));

      try {
        const r = await frappe.call({ doc: frm.doc, method: 'get_token' });
        const token = r.message;
        if (!token) return frappe.msgprint(__('Could not fetch token.'));

        frappe.confirm(
          __('This will wipe the saved WhatsApp session for tenant <b>{0}</b> and require re-pairing. Continue?', [frappe.utils.escape_html(tenant)]),
          () => {
            const host = window.location.hostname;
            const url  = `https://${host}:3001/qr?tenant=${encodeURIComponent(tenant)}&token=${encodeURIComponent(token)}&force=1&wipe=1`;
            window.open(url, '_blank', 'noopener');
          }
        );
      } catch (e) {
        frappe.msgprint(__('Failed to re-init: {0}', [e.message || e]));
      }
    }).addClass('btn-danger');


  }
});

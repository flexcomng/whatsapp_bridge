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

    frm.add_custom_button('Apply & Restart', async () => {
      try {
        frappe.show_alert({ message: __('Applying…'), indicator: 'orange' });
        const r = await frappe.call({ method: 'whatsapp_bridge.api.api.apply_settings' });
        frappe.msgprint(__('Bridge applied & restarted.'));
      } catch {
        frappe.msgprint(__('Apply failed'));
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

    frm.add_custom_button('Open QR', () => {
      const tenant = frm.doc.tenant_id || '';
      const token  = frm.doc.bridge_token || '';

      // Bridge vhost listens on HTTPS :3001 (SNI), same hostname as the site
      const host = window.location.hostname;
      const url  = `https://${host}:3001/qr?tenant=${encodeURIComponent(tenant)}&token=${encodeURIComponent(token)}`;

      window.open(url, '_blank', 'noopener');
    });
  }
});

# Copyright (c) 2024, Frappe and contributors
# See license.txt

import frappe


@frappe.whitelist(allow_guest=True, xss_safe=True)
def hook(*args, **kwargs):
	webhook = frappe.get_doc(
		{
			"doctype": "Sentry Webhook Log",
			"payload": frappe.request.get_data(as_text=True),
			"signature": frappe.request.headers.get('sentry-hook-signature'),
		}
	)
	try:
		webhook.insert(ignore_permissions=True)
		frappe.db.commit()
	except Exception as e:
		frappe.log_error("Sentry Webhook Insert Error")
		raise e


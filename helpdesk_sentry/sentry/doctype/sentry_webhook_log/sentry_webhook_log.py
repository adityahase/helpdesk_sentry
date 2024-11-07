# Copyright (c) 2024, Frappe and contributors
# For license information, please see license.txt

import json

from frappe.model.document import Document


class SentryWebhookLog(Document):
	def before_insert(self):
		self.set_fields()

	def set_fields(self):
		payload = json.loads(self.payload)
		event = payload.get("data", {}).get("event", {})

		self.issue_id = event.get("issue_id")

		# Truncate long strings to fit in Data field
		self.title = event.get("title", "")[:139]
		self.transaction = event.get("transaction", "")[:139]

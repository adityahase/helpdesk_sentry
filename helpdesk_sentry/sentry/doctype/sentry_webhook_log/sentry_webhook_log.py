# Copyright (c) 2024, Frappe and contributors
# For license information, please see license.txt

import hashlib
import hmac
import json

import frappe
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

	def validate(self):
		self.validate_signature()

	def validate_signature(self):
		client_secret = frappe.get_single("Sentry Settings").get_password("client_secret")
		computed_signature = hmac.new(
			key=client_secret.encode('utf-8'),
			msg=self.payload.encode('utf-8'),
			digestmod=hashlib.sha256,
		).hexdigest()

		if not hmac.compare_digest(computed_signature, self.signature):
			raise frappe.AuthenticationError

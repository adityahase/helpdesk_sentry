# Copyright (c) 2024, Frappe and contributors
# For license information, please see license.txt

import hashlib
import hmac
import json
from functools import cached_property

import frappe
from frappe.model.document import Document


class SentryWebhookLog(Document):
	def before_insert(self):
		self.set_fields()

	def set_fields(self):
		event = self.data.get("event", {})

		self.issue_id = event.get("issue_id")

		# Truncate long strings to fit in Data field
		self.title = event.get("title", "")[:139]
		self.transaction = event.get("transaction", "")[:139]
		self.triggered_rule = self.data.get("triggered_rule", "")[:139]

	def validate(self):
		self.validate_signature()

	def validate_signature(self):
		client_secret = self.settings.get_password("client_secret")
		computed_signature = hmac.new(
			key=client_secret.encode("utf-8"),
			msg=self.payload.encode("utf-8"),
			digestmod=hashlib.sha256,
		).hexdigest()

		if not hmac.compare_digest(computed_signature, self.signature):
			raise frappe.AuthenticationError

	def after_insert(self):
		current_user = frappe.session.user
		frappe.set_user(self.settings.support_user)
		frappe.enqueue_doc(
			self.doctype, self.name, method="process_webhook", queue="long", enqueue_after_commit=True
		)
		frappe.set_user(current_user)

	@frappe.whitelist()
	def process_webhook(self):
		if self.triggered_rule in self.alert_rules:
			self.create_or_set_ticket()

	def create_or_set_ticket(self):
		"""
		1. If there is an open ticket for the same issue, then set the ticket in the log.
		2. If there is no open ticket, then create a new ticket.
		"""
		if ticket := self.get_open_ticket():
			self.ticket = ticket[0].name
			self.save()
		else:
			self.create_support_ticket()

	def get_open_ticket(self):
		return frappe.db.sql(
			"""
			SELECT ticket.name
			FROM `tabSentry Webhook Log` log
			LEFT JOIN `tabHD Ticket` ticket ON log.ticket = ticket.name
			WHERE log.name != %s AND log.issue_id = %s AND log.ticket IS NOT NULL AND ticket.status = 'Open'
			ORDER BY log.creation DESC
			LIMIT 1
		""",
			(self.name, self.issue_id),
			as_dict=True,
		)

	def create_support_ticket(self):
		try:
			ticket = frappe.new_doc("HD Ticket")
			ticket.subject = f"[Sentry] {self.title}"[:139]
			ticket.raised_by = self.settings.support_user
			ticket.custom_app = "Sentry"
			ticket.agent_group = self.alert_rules.get(self.triggered_rule)
			ticket.ticket_type = self.settings.ticket_type
			link = self.data.get("event", {}).get("web_url", "")
			ticket.description = f"""<p>
			This is auto-generated ticket because an error occurred 10+ times and affects multiple users.<br>

			<a href={link} target="_blank">Click here to see more details on sentry</a>
			<br><br>

			Note:<br>
			1. If you fixed the problem, then mark it resolved or resolved in next release.<br>
			2. If the error seems invalid or entirely harmless, then you can "ignore" it and it won't be reported again.<br>
			</p>
			"""
			ticket.insert(ignore_permissions=True)
		except Exception:
			frappe.log_error("Sentry Alert Error")
		else:
			self.ticket = ticket.name
			self.save()

	@cached_property
	def data(self):
		return json.loads(self.payload).get("data", {})

	@cached_property
	def alert_rules(self):
		return {rule.alert_rule: rule.agent_group for rule in self.settings.alert_rules}

	@cached_property
	def settings(self):
		return frappe.get_single("Sentry Settings")

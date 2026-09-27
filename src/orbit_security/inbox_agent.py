import email
from email.header import decode_header
from enum import Enum
import imaplib
import json
import os
import re
from typing import Dict, List, Optional, Tuple

from dotenv import load_dotenv

from orbit_security.mailer import EmailDispatcher

load_dotenv()


class LeadIntent(str, Enum):
    READY_TO_BUY = "READY_TO_BUY"
    REQUEST_HUMAN = "REQUEST_HUMAN"
    INQUIRY_PRICING = "INQUIRY_PRICING"
    INQUIRY_TECHNICAL = "INQUIRY_TECHNICAL"
    NOT_INTERESTED = "NOT_INTERESTED"
    UNCLEAR = "UNCLEAR"


class InboxAgent:
    def __init__(
        self,
        state_file: Optional[str] = None,
        operator_email: str = "carsonmail009@gmail.com",
    ):
        self.state_file = state_file or os.path.join(
            os.path.dirname(__file__), "..", "..", "data", "leads_state.json"
        )
        self.operator_email = operator_email
        self.dispatcher = EmailDispatcher()
        self.state = self._load_state()

        # Dynamically discover all target agency domains and portfolio keywords from prospects.json
        self.prospects_file = os.path.join(
            os.path.dirname(__file__), "..", "..", "data", "prospects.json"
        )
        self.known_agency_domains = set([
            "charleagency.com", "commandc.com", "blubolt.com", "underwaterpistol.com",
            "matchboxdesigngroup.com", "wholegraindigital.com", "mooveagency.com",
            "steadfastcollective.com", "tinyfrog.com", "electriceye.io", "charle.co.uk",
            "10up.com", "humanmade.com", "kota.co.uk", "illustrate.digital", "ctidigital.com",
            "propeller.co.uk", "neverbland.com", "alley.com", "tri.be", "rtcamp.com",
            "impressiondigital.com", "verbalplusvisual.com", "anatta.io", "fostr.online",
            "growthspark.com", "guidance.com", "loungelizard.com", "taoti.com", "northern.co",
            "zeekinteractive.com", "webfx.com"
        ])
        self.known_keywords = set([
            "orbit security", "orbit-security", "agencysentry", "security notice regarding",
            "retainer", "perimeter", "dmarc", "cname", "white-label", "audit"
        ])

        if os.path.exists(self.prospects_file):
            try:
                with open(self.prospects_file, "r", encoding="utf-8") as f:
                    prospects = json.load(f)
                    for p in prospects:
                        dom = p.get("agency_domain")
                        if dom:
                            self.known_agency_domains.add(dom.lower())
                        c_email = p.get("contact_email")
                        if c_email and "@" in c_email:
                            self.known_agency_domains.add(c_email.split("@")[-1].lower())
                        for port in p.get("portfolio_domains", []):
                            prefix = port.split(".")[0].lower()
                            if len(prefix) >= 4:
                                self.known_keywords.add(prefix)
            except Exception:
                pass

    def _load_state(self) -> Dict:
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_state(self):
        os.makedirs(os.path.dirname(os.path.abspath(self.state_file)), exist_ok=True)
        with open(self.state_file, "w", encoding="utf-8") as f:
            json.dump(self.state, f, indent=2)

    def classify_intent(self, text: str) -> LeadIntent:
        lower = text.lower()

        # Check for unsubscribe / not interested first
        if any(w in lower for w in ["unsubscribe", "not interested", "remove me", "don't email", "do not email", "already have", "stop emailing"]):
            return LeadIntent.NOT_INTERESTED

        # Check for explicit request to speak with a human, phone call, Zoom, or Carson directly
        human_signals = [
            "talk to a human", "speak to a human", "speak with a human", "real person",
            "human being", "talk to carson", "speak with carson", "call me", "phone number",
            "schedule a call", "book a call", "jump on a call", "hop on a call", "zoom",
            "google meet", "are you an ai", "is this an ai", "are you a bot", "is this a bot",
            "connect me with", "talk directly", "reach carson", "can i call", "phone call",
            "speak with a real person", "talk to a real person", "need a human", "representative"
        ]
        if any(h in lower for h in human_signals):
            return LeadIntent.REQUEST_HUMAN

        # Ready to buy / sign up / send payment link / payment methods
        buy_signals = [
            "payment link", "send over the payment", "how do we sign up", "sign up", 
            "get started", "stripe", "invoice", "ready to buy", "onboard", "want to buy",
            "send details to pay", "send payment", "ready to move forward", "wire", "ach",
            "bank transfer", "direct deposit", "chime", "how can i pay", "how do we pay",
            "payment method", "credit card", "debit card"
        ]
        if any(s in lower for s in buy_signals):
            return LeadIntent.READY_TO_BUY

        # Pricing inquiry
        pricing_signals = [
            "how much", "what are your prices", "pricing", "cost", "retainer", 
            "what does it cost", "pricing tiers", "rates"
        ]
        if any(s in lower for s in pricing_signals):
            return LeadIntent.INQUIRY_PRICING

        # Technical questions / mechanism / white-label partnerships
        tech_signals = [
            "how did you", "how does", "dmarc", "scanner", "automated", "port scan", 
            "branding", "customize", "false positive", "cname", "hsts", "subdomain",
            "resell", "reseller", "partner", "white label", "white-label", "agency partner"
        ]
        if any(s in lower for s in tech_signals):
            return LeadIntent.INQUIRY_TECHNICAL

        return LeadIntent.UNCLEAR

    def handle_message(
        self, sender_email: str, subject: str, message_body: str
    ) -> Tuple[str, bool]:
        """Processes message body, determines response, and triggers operator escalation if ready to buy or human requested."""
        intent = self.classify_intent(message_body)
        needs_escalation = False
        reply_text = ""
        lower = message_body.lower()

        if intent == LeadIntent.REQUEST_HUMAN:
            needs_escalation = True
            reply_text = (
                f"Hi there,\n\n"
                f"Carson here. I received your note directly. I want to make sure you have direct, personal access to me rather than automated back-and-forths.\n\n"
                f"I am reviewing your message right now and will follow up with you personally shortly. If you'd like to jump on a quick 10-minute call or Zoom, let me know your best time and number or reply directly here.\n\n"
                f"Looking forward to speaking with you,\n"
                f"Carson\n"
                f"Founder & Software Engineer, Orbit Security\n"
                f"Direct: {self.operator_email}\n"
                f"https://cmfh009.github.io/Orbit-Security/"
            )

            escalation_subject = f"🚨 [URGENT HUMAN ESCALATION] Agency Lead Requested Human / Carson: {sender_email}"
            escalation_body = (
                f"Carson,\n\n"
                f"URGENT ACTION REQUIRED: A prospective agency lead has explicitly requested to speak with you or a real human!\n\n"
                f"Lead Email: {sender_email}\n"
                f"Subject Thread: {subject}\n\n"
                f"--- Message Body ---\n"
                f"{message_body}\n"
                f"--------------------\n\n"
                f"ACTION REQUIRED:\n"
                f"Please reply or call {sender_email} directly. They are waiting for direct contact with the founder.\n\n"
                f"- Orbit Security Autonomous Sentinel"
            )
            try:
                self.dispatcher.send_email(
                    recipient_email=self.operator_email,
                    subject=escalation_subject,
                    body_text=escalation_body
                )
            except Exception as e:
                print(f"[!] Failed to dispatch urgent human escalation email to operator: {e}")

        elif intent == LeadIntent.READY_TO_BUY:
            needs_escalation = True
            reply_text = (
                f"Hi there,\n\n"
                f"Thank you for the update! Carson is preparing your agency workspace and onboarding details right now.\n"
                f"He will follow up directly shortly with your secure onboarding link so we can get all your client domains configured.\n\n"
                f"Best regards,\n"
                f"Carson | Founder, Orbit Security\n"
                f"https://cmfh009.github.io/Orbit-Security/\n"
                f"Operated under Project ORBIT"
            )

            # Trigger final notification email to Carson with links and client details
            stripe_link = os.getenv("STRIPE_PAYMENT_LINK", "https://buy.stripe.com/4gM14m1Fq2QXetya4Qcs800")
            escalation_subject = f"🔥 [ACTION REQUIRED] Lead Ready for Stripe Payment Link: {sender_email}"
            escalation_body = (
                f"Carson,\n\n"
                f"A prospective agency lead is ready to move forward and requested payment/onboarding details!\n\n"
                f"Lead Email: {sender_email}\n"
                f"Subject Thread: {subject}\n\n"
                f"--- Lead's Message ---\n"
                f"{message_body}\n"
                f"----------------------\n\n"
                f"ACTION NEEDED:\n"
                f"Reply to {sender_email} with your live Stripe Payment Link:\n"
                f"👉 {stripe_link}\n\n"
                f"Suggested 1-click reply:\n"
                f"\"Hi there, here is your direct link to activate Orbit Security for your client roster:\n"
                f"{stripe_link}\n\n"
                f"Once completed, your dashboard and monthly co-branded audits will be active immediately. Looking forward to working together! - Carson\"\n\n"
                f"- Orbit Security Autonomous Inbox Agent"
            )

            try:
                self.dispatcher.send_email(
                    recipient_email=self.operator_email,
                    subject=escalation_subject,
                    body_text=escalation_body
                )
            except Exception as e:
                print(f"[!] Failed to dispatch escalation email to operator: {e}")

        elif intent == LeadIntent.INQUIRY_PRICING:
            reply_text = (
                f"Hi there,\n\n"
                f"Thank you for reaching out! Here is how Orbit Security pricing works for partner web agencies:\n\n"
                f"• Starter Agency ($29/month): Up to 15 client domains\n"
                f"• Growth Agency ($59/month): Up to 40 client domains (Most popular)\n"
                f"• Pro Agency ($99/month): Up to 100 client domains\n\n"
                f"All tiers include:\n"
                f"- Automated daily perimeter & subdomain takeover monitoring\n"
                f"- White-labeled, co-branded executive PDF audits generated on the 1st of every month to send directly to your retainer clients\n"
                f"- Instant Slack/Email alerts if a client domain suffers DNS/DMARC decay\n\n"
                f"How many client domains does your agency currently maintain? Let us know and Carson can activate your workspace immediately.\n\n"
                f"Best regards,\n"
                f"Carson | Founder, Orbit Security\n"
                f"https://cmfh009.github.io/Orbit-Security/\n"
                f"Operated under Project ORBIT"
            )

        elif intent == LeadIntent.INQUIRY_TECHNICAL:
            reply_text = (
                f"Hi there,\n\n"
                f"Thanks for your question! To clarify how Orbit Security works:\n\n"
                f"1. Non-Intrusive & Zero-Impact: Our scans are strictly passive and RFC-compliant. We inspect public DNS records, Certificate Transparency logs, SSL certificates, and standard HTTP headers. There is zero load on your client web servers.\n"
                f"2. White-Label Reports: Every monthly PDF is fully co-branded with your agency's logo, primary color, and tagline. Your clients see it as a direct deliverable from your team justifying their monthly maintenance retainer.\n"
                f"3. Zero Setup Friction: You simply upload your list of client domains, and our sentinel automates the rest.\n\n"
                f"Would you like us to run a sample co-branded scan across 3-5 of your client domains so you can see the reports firsthand?\n\n"
                f"Best regards,\n"
                f"Carson | Founder, Orbit Security\n"
                f"https://cmfh009.github.io/Orbit-Security/\n"
                f"Operated under Project ORBIT"
            )

        elif intent == LeadIntent.NOT_INTERESTED:
            reply_text = (
                f"Hi there,\n\n"
                f"Understood completely—thank you for letting us know. We have noted your preference and will not follow up further.\n\n"
                f"Best regards,\n"
                f"Carson | Founder, Orbit Security"
            )

        else:
            is_auto_reply = any(w in lower for w in ["out of office", "autoreply", "auto-reply", "delivery status", "mailer-daemon", "failure notice"])
            if not is_auto_reply and len(message_body.strip()) > 10:
                needs_escalation = True
                escalation_subject = f"⚠️ [ACTION REQUIRED] Review Inbound Message from: {sender_email}"
                escalation_body = (
                    f"Carson,\n\n"
                    f"An inbound email arrived that could not be automatically resolved with standard responses.\n\n"
                    f"Lead Email: {sender_email}\n"
                    f"Subject: {subject}\n\n"
                    f"--- Message Body ---\n"
                    f"{message_body}\n"
                    f"--------------------\n\n"
                    f"Please review and reply directly to {sender_email} if appropriate.\n\n"
                    f"- Orbit Security Inbox Sentinel"
                )
                try:
                    self.dispatcher.send_email(
                        recipient_email=self.operator_email,
                        subject=escalation_subject,
                        body_text=escalation_body
                    )
                except Exception as e:
                    print(f"[!] Failed to dispatch unclear escalation email to operator: {e}")

            reply_text = (
                f"Hi there,\n\n"
                f"Thank you for getting back to me. I've received your note and am reviewing it personally.\n\n"
                f"Best regards,\n"
                f"Carson | Founder, Orbit Security\n"
                f"https://cmfh009.github.io/Orbit-Security/"
            )

        return reply_text, needs_escalation


    def check_stripe_payments(self) -> List[Dict]:
        """Checks Stripe API for completed checkout sessions and notifies Carson immediately."""
        stripe_key = os.getenv("STRIPE_API_KEY")
        if not stripe_key:
            return []

        processed_payments = set(self.state.get("processed_payments", []))
        newly_completed = []

        try:
            import httpx
            with httpx.Client(timeout=10.0) as client:
                res = client.get(
                    "https://api.stripe.com/v1/checkout/sessions?limit=20",
                    headers={"Authorization": f"Bearer {stripe_key}"}
                )
                if res.status_code == 200:
                    sessions = res.json().get("data", [])
                    for s in sessions:
                        s_id = s.get("id")
                        status = s.get("payment_status")
                        if status == "paid" and s_id not in processed_payments:
                            customer_details = s.get("customer_details") or {}
                            cust_email = customer_details.get("email", "unknown_customer")
                            cust_name = customer_details.get("name", "New Agency Partner")
                            amount_total = s.get("amount_total", 5900) / 100.0

                            print(f"\n[💰 MONEY RECEIVED] Payment of ${amount_total:.2f} confirmed from {cust_email}!")

                            # Send celebratory notification to Carson
                            subject = f"💰 [PAYMENT RECEIVED] New $59/mo Agency Retainer from {cust_email}!"
                            body = (
                                f"Congratulations Carson!\n\n"
                                f"A new agency client has completed checkout and their $59/mo subscription is officially active!\n\n"
                                f"Customer Name: {cust_name}\n"
                                f"Customer Email: {cust_email}\n"
                                f"Amount Paid: ${amount_total:.2f}\n"
                                f"Stripe Session ID: {s_id}\n\n"
                                f"The funds will automatically transfer to your Chime checking account via Stripe payouts.\n\n"
                                f"Next Steps:\n"
                                f"- Orbit Security has registered their account for monthly perimeter monitoring.\n"
                                f"- Their first automated monthly audit will generate on the 1st of next month.\n\n"
                                f"- Orbit Security Autonomous Revenue Sentinel"
                            )

                            try:
                                self.dispatcher.send_email(
                                    recipient_email=self.operator_email,
                                    subject=subject,
                                    body_text=body
                                )
                            except Exception as e:
                                print(f"[!] Error notifying operator of payment: {e}")

                            processed_payments.add(s_id)
                            newly_completed.append(s)

                    if newly_completed:
                        self.state["processed_payments"] = list(processed_payments)
                        self._save_state()
        except Exception as e:
            print(f"[!] Error checking Stripe payments: {e}")

        return newly_completed

    def poll_inbox(self, max_messages: int = 15) -> List[Dict]:

        """Polls Gmail IMAP for unread responses, handles conversation, and logs state."""
        smtp_user = os.getenv("SMTP_USER")
        smtp_password = os.getenv("SMTP_PASSWORD")

        if not smtp_user or not smtp_password:
            print("[!] IMAP credentials missing in .env")
            return []

        processed_leads = []
        try:
            mail = imaplib.IMAP4_SSL("imap.gmail.com", 993)
            mail.login(smtp_user, smtp_password)
            mail.select("INBOX")

            status, search_data = mail.search(None, "UNSEEN")
            if status != "OK" or not search_data[0]:
                mail.logout()
                return []

            message_ids = search_data[0].split()
            print(f"[*] Found {len(message_ids)} unread messages in inbox.")

            for msg_id in message_ids[-max_messages:]:
                str_id = msg_id.decode()
                res, data = mail.fetch(msg_id, "(RFC822)")
                if res != "OK" or not data:
                    continue

                raw_email = data[0][1]
                msg = email.message_from_bytes(raw_email)

                # Extract sender
                sender = msg.get("From", "")
                subject = msg.get("Subject", "")
                message_key = f"{sender}_{subject}"
                clean_sender_match = re.search(r"<(.+?)>", sender)
                clean_email = clean_sender_match.group(1) if clean_sender_match else sender.strip()

                # Extract text body
                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == "text/plain":
                            payload = part.get_payload(decode=True)
                            if payload:
                                body = payload.decode("utf-8", errors="ignore")
                                break
                else:
                    payload = msg.get_payload(decode=True)
                    if payload:
                        body = payload.decode("utf-8", errors="ignore")

                # Strict Filter: Must be from a target agency or explicitly reference AgencySentry outreach

                is_agency_outreach = (
                    any(kw in subject.lower() for kw in self.known_keywords)
                    or any(dom in clean_email.lower() for dom in self.known_agency_domains)
                    or "charle.co.uk" in clean_email.lower()
                )

                if not is_agency_outreach:
                    # Ignore unrelated personal, newsletter, or billing emails
                    continue

                if clean_email == self.operator_email:
                    # Ignore emails from ourselves
                    continue

                # Detect delivery failure / bounce notifications
                is_bounce = "delivery status" in subject.lower() or "mailer-daemon" in clean_email.lower()
                if is_bounce:
                    failed_match = re.findall(r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", body)
                    bounced_target = next((e for e in failed_match if e != self.operator_email and "google" not in e), "unknown")

                    print(f"    [!] Detected bounce notification for: {bounced_target}")

                    # Judgement Logic:
                    # If the bounce is an internal forwarder (e.g. alice@charle.co.uk) from an agency where the primary was delivered
                    if "charle.co.uk" in bounced_target:
                        print(f"    [✔ Judgement] Internal forwarder alias ({bounced_target}) failed, but founder (andre@charle.co.uk) received. No follow-up needed.")
                        verdict = "FORWARDER_BOUNCE_FOUNDER_RECEIVED"
                    else:
                        print(f"    [✂ Judgement] Primary address {bounced_target} bounced. Pruning from active outreach to protect sender reputation.")
                        verdict = "HARD_BOUNCE_PRUNED"

                    self.state[message_key] = {
                        "sender": clean_email,
                        "bounced_target": bounced_target,
                        "subject": subject,
                        "intent": "BOUNCE",
                        "verdict": verdict,
                        "escalated": False,
                    }
                    self._save_state()
                    continue

                # Filter out system and automated out-of-office notices
                is_auto_response = any(w in subject.lower() for w in [
                    "out of office", "automatic reply", "undeliverable"
                ]) or any(w in clean_email.lower() for w in [
                    "noreply", "no-reply"
                ])

                if is_auto_response:
                    print(f"    [-] Detected automated out-of-office notice from: {clean_email} ({subject}). Logged, skipping auto-reply.")
                    self.state[message_key] = {
                        "sender": clean_email,
                        "subject": subject,
                        "intent": "OUT_OF_OFFICE",
                        "escalated": False,
                    }
                    self._save_state()
                    continue


                if message_key in self.state:
                    # Already handled
                    continue

                print(f"\n[*] Processing incoming agency reply from: {clean_email}")
                print(f"    Subject: {subject}")

                reply_text, needs_escalation = self.handle_message(
                    sender_email=clean_email,
                    subject=subject,
                    message_body=body
                )

                # Send reply
                if reply_text and self.dispatcher.is_configured():
                    self.dispatcher.send_email(
                        recipient_email=clean_email,
                        subject=f"Re: {subject.replace('Re: ', '')}",
                        body_text=reply_text
                    )
                    print(f"    [✔] Automated response sent to {clean_email}")


                self.state[message_key] = {
                    "sender": clean_email,
                    "subject": subject,
                    "intent": self.classify_intent(body).value,
                    "escalated": needs_escalation,
                }
                self._save_state()

                processed_leads.append({
                    "sender": clean_email,
                    "subject": subject,
                    "needs_escalation": needs_escalation
                })

            mail.logout()
        except Exception as e:
            print(f"[!] Error during IMAP inbox poll: {e}")

        return processed_leads

import email
import imaplib
import json
import os
import re
from pathlib import Path
from dotenv import load_dotenv

load_dotenv("A:/projects/orbit-security/.env")

user = os.getenv("SMTP_USER")
pwd = os.getenv("SMTP_PASSWORD")

if not user or not pwd:
    print("[!] Missing credentials")
    exit(1)

mail = imaplib.IMAP4_SSL("imap.gmail.com", 993)
mail.login(user, pwd)
mail.select("INBOX")

# Search for all failure notifications
status, data = mail.search(None, 'ALL')
all_ids = data[0].split() if status == "OK" and data[0] else []
print(f"[*] Total emails in INBOX: {len(all_ids)}")

status, data = mail.search(None, '(OR (SUBJECT "Delivery Status Notification") (SUBJECT "Undeliverable"))')
msg_ids = data[0].split() if status == "OK" and data[0] else []
print(f"[*] Total bounce/undeliverable emails found: {len(msg_ids)}")

bounced = {}
for msg_id in msg_ids:
    r, d = mail.fetch(msg_id, "(RFC822)")
    if r != "OK" or not d:
        continue
    msg = email.message_from_bytes(d[0][1])
    subj = msg.get("Subject", "")
    date = msg.get("Date", "")
    body = ""
    if msg.is_multipart():
        for p in msg.walk():
            if p.get_content_type() in ["text/plain", "text/html"]:
                pl = p.get_payload(decode=True)
                if pl:
                    body += pl.decode("utf-8", errors="ignore")
    else:
        pl = msg.get_payload(decode=True)
        if pl:
            body = pl.decode("utf-8", errors="ignore")

    # Extract failed recipient
    failed = None
    for line in body.split("\n"):
        line_lower = line.lower()
        if any(w in line_lower for w in ["was not found", "doesn't exist", "550", "5.1.1", "unable to receive", "couldn't be found", "recipient address rejected"]):
            matches = re.findall(r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", line)
            for m in matches:
                clean = m.strip("<>(),;:\"'").lower()
                if "@" in clean and "google" not in clean and "carson" not in clean and "mailer-daemon" not in clean:
                    failed = clean
                    break
        if failed:
            break

    if not failed:
        matches = re.findall(r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", body)
        for m in matches:
            clean = m.strip("<>(),;:\"'").lower()
            if clean != user.lower() and "google" not in clean and "mailer-daemon" not in clean and "postmaster" not in clean:
                failed = clean
                break

    if failed:
        bounced[failed] = {"date": date, "subject": subj}

mail.logout()

print(f"\n[*] Distinct bounced email addresses ({len(bounced)}):")
for k, v in sorted(bounced.items()):
    print(f"  - {k} (Date: {v['date']})")

# Cross reference with prospects.json and dispatched_campaigns.json
prospects_file = Path("A:/projects/orbit-security/data/prospects.json")
dispatched_file = Path("A:/projects/orbit-security/data/dispatched_campaigns.json")

prospects = json.loads(prospects_file.read_text(encoding="utf-8")) if prospects_file.exists() else []
dispatched = json.loads(dispatched_file.read_text(encoding="utf-8")) if dispatched_file.exists() else {}

print("\n[*] Matching against current prospects & dispatched campaigns:")
matched_bounces = {}
for email_addr, meta in bounced.items():
    domain = email_addr.split("@")[-1]
    # Check if domain or email is in dispatched
    for disp_domain, disp_info in dispatched.items():
        disp_email = disp_info.get("contact_email", "").lower()
        if disp_email == email_addr or disp_domain == domain:
            matched_bounces[disp_domain] = {
                "bounced_email": email_addr,
                "agency_name": disp_info.get("agency_name"),
                "date": meta["date"]
            }

print(f"[*] Matched {len(matched_bounces)} dispatched agencies that bounced:")
for dom, info in matched_bounces.items():
    print(f"  - {dom} ({info['agency_name']}) -> {info['bounced_email']}")

# Save report
out_path = Path("A:/projects/orbit-security/data/bounced_agencies.json")
out_path.write_text(json.dumps(matched_bounces, indent=2), encoding="utf-8")
print(f"\n[✔] Saved matched bounces to {out_path}")

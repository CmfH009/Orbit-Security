import email
import imaplib
import os
import re
from dotenv import load_dotenv

load_dotenv()

def inspect_bounces():
    user = os.getenv("SMTP_USER")
    pwd = os.getenv("SMTP_PASSWORD")
    if not user or not pwd:
        print("[!] Missing credentials")
        return

    mail = imaplib.IMAP4_SSL("imap.gmail.com", 993)
    mail.login(user, pwd)
    mail.select("INBOX")

    status, data = mail.search(None, '(SUBJECT "Delivery Status Notification")')
    if status != "OK" or not data[0]:
        print("[*] No Delivery Status Notification emails found.")
        mail.logout()
        return

    msg_ids = data[0].split()
    print(f"[*] Found {len(msg_ids)} Delivery Status Notification emails.")

    bounced_emails = []
    for msg_id in msg_ids[-10:]:
        res, fetch_data = mail.fetch(msg_id, "(RFC822)")
        if res != "OK" or not fetch_data:
            continue
        msg = email.message_from_bytes(fetch_data[0][1])
        subject = msg.get("Subject", "")

        # Extract text body or failure recipient
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    p = part.get_payload(decode=True)
                    if p:
                        body += p.decode("utf-8", errors="ignore")
        else:
            p = msg.get_payload(decode=True)
            if p:
                body = p.decode("utf-8", errors="ignore")

        # Find failed email in body
        match = re.search(r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", body)
        # Look for "The response from the remote server was:" or "Address not found"
        target_match = re.findall(r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", body)
        
        # Look specifically for lines with "was not found" or "550" or "failed"
        failed_address = None
        for line in body.split("\n"):
            if "was not found" in line.lower() or "doesn't exist" in line.lower() or "550" in line or "5.1.1" in line:
                for word in line.split():
                    if "@" in word and "google" not in word and "carson" not in word:
                        clean_w = word.strip("<>(),;:\"'")
                        failed_address = clean_w
                        break

        # Fallback search
        if not failed_address:
            for em in target_match:
                if em != user and "google" not in em:
                    failed_address = em
                    break

        bounced_emails.append({
            "subject": subject,
            "failed_address": failed_address,
            "snippet": body[:300].replace("\n", " ")
        })

    mail.logout()

    print("\n--- Bounced Email Summary ---")
    seen = set()
    for b in bounced_emails:
        addr = b["failed_address"]
        if addr and addr not in seen:
            seen.add(addr)
            print(f"[!] Bounced: {addr}")
            print(f"    Snippet: {b['snippet'][:150]}...")

    return list(seen)

if __name__ == "__main__":
    inspect_bounces()

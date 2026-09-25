import email
import imaplib
import os
from dotenv import load_dotenv

load_dotenv()

def print_detailed_bounces():
    mail = imaplib.IMAP4_SSL("imap.gmail.com", 993)
    mail.login(os.getenv("SMTP_USER"), os.getenv("SMTP_PASSWORD"))
    mail.select("INBOX")

    status, data = mail.search(None, '(SUBJECT "Delivery Status Notification")')
    if not data[0]:
        print("No bounces found.")
        mail.logout()
        return

    msg_ids = data[0].split()
    print(f"Total delivery notifications: {len(msg_ids)}")

    for msg_id in msg_ids:
        res, fetch_data = mail.fetch(msg_id, "(RFC822)")
        msg = email.message_from_bytes(fetch_data[0][1])
        print("="*60)
        print("Subject:", msg.get("Subject"))
        print("Date:", msg.get("Date"))
        
        # walk parts
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype in ("text/plain", "message/delivery-status"):
                p = part.get_payload(decode=True)
                if p:
                    text = p.decode("utf-8", errors="ignore")
                    print("--- BODY CHUNK ---")
                    print(text[:400])

    mail.logout()

if __name__ == "__main__":
    print_detailed_bounces()

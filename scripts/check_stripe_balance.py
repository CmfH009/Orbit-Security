import os
import urllib.request
import json
import base64
from dotenv import load_dotenv

load_dotenv(r"A:\projects\orbit-security\.env")

api_key = os.getenv("STRIPE_API_KEY") or os.getenv("STRIPE_SECRET_KEY")
if not api_key:
    print("[!] STRIPE_API_KEY / STRIPE_SECRET_KEY not set in .env")
    exit(1)

auth_header = "Basic " + base64.b64encode(f"{api_key}:".encode()).decode()

def stripe_get(endpoint):
    req = urllib.request.Request(f"https://api.stripe.com/v1/{endpoint}")
    req.add_header("Authorization", auth_header)
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())

def main():
    print("[*] Querying Stripe REST API...")
    try:
        bal = stripe_get("balance")
        print("\n--- Stripe Balance ---")
        for item in bal.get("available", []):
            print(f"Available: {item.get('amount') / 100:.2f} {item.get('currency', '').upper()}")
        for item in bal.get("pending", []):
            print(f"Pending:   {item.get('amount') / 100:.2f} {item.get('currency', '').upper()}")
        
        charges = stripe_get("charges?limit=10")
        charge_list = charges.get("data", [])
        print(f"\n--- Recent Charges ({len(charge_list)}) ---")
        if not charge_list:
            print("No charges recorded yet.")
        for c in charge_list:
            print(f"  ID: {c.get('id')} | Amount: {c.get('amount')/100:.2f} {c.get('currency', '').upper()} | Status: {c.get('status')} | Customer: {c.get('billing_details', {}).get('name') or c.get('billing_details', {}).get('email')}")

        sessions = stripe_get("checkout/sessions?limit=10")
        session_list = sessions.get("data", [])
        print(f"\n--- Recent Checkout Sessions ({len(session_list)}) ---")
        if not session_list:
            print("No checkout sessions recorded yet.")
        for s in session_list:
            cust_details = s.get('customer_details') or {}
            cust_email = cust_details.get('email') or s.get('customer_email') or 'N/A'
            print(f"  ID: {s.get('id')} | Status: {s.get('status')} | Payment: {s.get('payment_status')} | Customer: {cust_email}")
            
    except Exception as e:
        print(f"[!] Error querying Stripe: {e}")

if __name__ == "__main__":
    main()

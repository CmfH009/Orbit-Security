import os
import json
import httpx
from dotenv import load_dotenv

load_dotenv()

STRIPE_KEY = os.getenv("STRIPE_API_KEY")
headers = {
    "Authorization": f"Bearer {STRIPE_KEY}"
}


def inspect_and_update():
    print("[*] Inspecting Stripe Products, Prices, and Payment Links...")
    with httpx.Client(timeout=15.0) as client:
        # 1. Inspect Products
        r_prods = client.get("https://api.stripe.com/v1/products", headers=headers)
        prods = r_prods.json().get("data", [])
        print(f"Found {len(prods)} product(s):")

        for p in prods:
            p_id = p["id"]
            p_name = p.get("name", "")
            print(f"  - Product {p_id}: {p_name}")

            # Update product name and statement descriptor
            update_data = {
                "name": "Orbit Security — Agency Growth Plan",
                "description": "Continuous external attack surface monitoring, subdomain takeover sentinel, and white-labeled monthly PDF perimeter audits for web and Shopify agencies.",
                "statement_descriptor": "ORBIT*SECURITY"
            }
            r_up = client.post(f"https://api.stripe.com/v1/products/{p_id}", headers=headers, data=update_data)
            if r_up.status_code == 200:
                print(f"    [✔] Successfully updated {p_id} to 'Orbit Security — Agency Growth Plan' (Statement Descriptor: ORBIT*SECURITY)")
            else:
                # If statement_descriptor fails (some account types don't permit per-product statement_descriptor), try without it
                print(f"    [!] Update with statement_descriptor returned {r_up.status_code}: {r_up.text}")
                update_data.pop("statement_descriptor", None)
                r_up2 = client.post(f"https://api.stripe.com/v1/products/{p_id}", headers=headers, data=update_data)
                if r_up2.status_code == 200:
                    print(f"    [✔] Updated product name & description without statement_descriptor")
                else:
                    print(f"    [!] Failed to update product {p_id}: {r_up2.text}")

        # 2. Inspect Payment Links
        r_links = client.get("https://api.stripe.com/v1/payment_links", headers=headers)
        links = r_links.json().get("data", [])
        print(f"\nPayment Link(s): {len(links)}")
        for l in links:
            print(f"  - Link {l['id']}: {l.get('url')} (Active: {l.get('active')})")

        # 3. Check / Configure Customer Portal if available
        try:
            r_portal = client.get("https://api.stripe.com/v1/billing_portal/configurations", headers=headers)
            if r_portal.status_code == 200:
                portals = r_portal.json().get("data", [])
                print(f"\nBilling Portal Configuration(s): {len(portals)}")
                if not portals:
                    # Attempt to create standard billing portal config
                    portal_data = {
                        "business_profile[headline]": "Orbit Security Labs — Agency Retainers",
                        "business_profile[privacy_policy_url]": "https://cmfh009.github.io/orbit-security#privacy",
                        "business_profile[terms_of_service_url]": "https://cmfh009.github.io/orbit-security#terms",
                        "features[customer_update][enabled]": "true",
                        "features[customer_update][allowed_updates][0]": "email",
                        "features[customer_update][allowed_updates][1]": "address",
                        "features[invoice_history][enabled]": "true",
                        "features[payment_method_update][enabled]": "true"
                    }
                    r_pcreate = client.post("https://api.stripe.com/v1/billing_portal/configurations", headers=headers, data=portal_data)
                    if r_pcreate.status_code in (200, 201):
                        print(f"  [✔] Created Customer Billing Portal configuration: {r_pcreate.json().get('id')}")
                    else:
                        print(f"  [!] Customer Portal creation response: {r_pcreate.status_code} - {r_pcreate.text}")
                else:
                    print(f"  [✔] Customer Billing Portal already active: {portals[0].get('id')}")
            else:
                print(f"  [!] Portal query status: {r_portal.status_code}")
        except Exception as e:
            print(f"  [!] Portal check error: {e}")


if __name__ == "__main__":
    inspect_and_update()

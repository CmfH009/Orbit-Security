import os
import httpx
from dotenv import load_dotenv

load_dotenv()

STRIPE_KEY = os.getenv("STRIPE_API_KEY")

headers = {
    "Authorization": f"Bearer {STRIPE_KEY}"
}

def create_payment_link():
    print("[*] Connecting to Stripe API with provided key...")
    
    # 1. Create or get Product with SaaS tax code
    prod_data = {
        "name": "AgencySentry - Website Maintenance Retainer (Growth Plan)",
        "description": "Continuous external attack surface monitoring and white-labeled monthly PDF perimeter audits for up to 40 client domains.",
        "tax_code": "txcd_10103001"  # SaaS - Software as a Service (Business Use)
    }

    
    with httpx.Client(timeout=10.0) as client:
        r_prod = client.post("https://api.stripe.com/v1/products", headers=headers, data=prod_data)
        if r_prod.status_code not in (200, 201):
            print(f"[!] Error creating product: {r_prod.status_code} - {r_prod.text}")
            return None
        
        prod_id = r_prod.json()["id"]
        print(f"[✔] Created Stripe Product: {prod_id}")
        
        # 2. Create Recurring Monthly Price ($59.00 USD/mo)
        price_data = {
            "product": prod_id,
            "unit_amount": "5900",  # $59.00
            "currency": "usd",
            "recurring[interval]": "month",
        }
        r_price = client.post("https://api.stripe.com/v1/prices", headers=headers, data=price_data)
        if r_price.status_code not in (200, 201):
            print(f"[!] Error creating price: {r_price.status_code} - {r_price.text}")
            return None
        
        price_id = r_price.json()["id"]
        print(f"[✔] Created Recurring Price: {price_id} ($59.00/mo)")
        
        # 3. Create Payment Link
        link_data = {
            "line_items[0][price]": price_id,
            "line_items[0][quantity]": "1",
        }
        r_link = client.post("https://api.stripe.com/v1/payment_links", headers=headers, data=link_data)
        if r_link.status_code not in (200, 201):
            print(f"[!] Error creating payment link: {r_link.status_code} - {r_link.text}")
            return None
        
        payment_url = r_link.json()["url"]
        print(f"\n=======================================================")
        print(f"[🔥 SUCCESS] Live Stripe Payment Link Created:")
        print(f"👉 {payment_url}")
        print(f"=======================================================\n")
        
        return payment_url

if __name__ == "__main__":
    create_payment_link()

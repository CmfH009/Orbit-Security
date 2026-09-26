import ctypes
from ctypes import wintypes
import subprocess
import httpx

class CREDENTIAL(ctypes.Structure):
    _fields_ = [
        ('Flags', wintypes.DWORD),
        ('Type', wintypes.DWORD),
        ('TargetName', wintypes.LPWSTR),
        ('Comment', wintypes.LPWSTR),
        ('LastWritten', wintypes.FILETIME),
        ('CredentialBlobSize', wintypes.DWORD),
        ('CredentialBlob', ctypes.POINTER(ctypes.c_byte)),
        ('Persist', wintypes.DWORD),
        ('AttributeCount', wintypes.DWORD),
        ('Attributes', ctypes.c_void_p),
        ('TargetAlias', wintypes.LPWSTR),
        ('UserName', wintypes.LPWSTR)
    ]

def get_token():
    advapi32 = ctypes.windll.advapi32
    CredReadW = advapi32.CredReadW
    CredReadW.argtypes = [wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.POINTER(CREDENTIAL))]
    CredReadW.restype = wintypes.BOOL
    pcred = ctypes.POINTER(CREDENTIAL)()
    target = 'GitHub - https://api.github.com/CmfH009'
    if CredReadW(target, 1, 0, ctypes.byref(pcred)):
        return ctypes.string_at(pcred.contents.CredentialBlob, pcred.contents.CredentialBlobSize).decode('utf-8')
    raise RuntimeError("Could not retrieve GitHub credential from Windows Credential Store")

def main():
    token = get_token()
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'OrbitSecurity'
    }

    # 1. Update repo metadata
    meta = {
        "description": "Orbit Security: Autonomous external perimeter hygiene, subdomain takeover sentinel, and white-label client security auditing for web & Shopify agencies.",
        "homepage": "https://cmfh009.github.io/Orbit-Security/"
    }
    r = httpx.patch("https://api.github.com/repos/CmfH009/Orbit-Security", headers=headers, json=meta)
    print(f"Update Repo Metadata: {r.status_code}")

    # 2. Update topics
    topics_payload = {
        "names": [
            "cybersecurity",
            "attack-surface-management",
            "subdomain-takeover",
            "dmarc",
            "web-agencies",
            "python",
            "security-auditor"
        ]
    }
    r_top = httpx.put("https://api.github.com/repos/CmfH009/Orbit-Security/topics", headers=headers, json=topics_payload)
    print(f"Update Topics: {r_top.status_code}")

    # 3. Push git commit
    remote_url = f"https://x-access-token:{token}@github.com/CmfH009/Orbit-Security.git"
    print("[*] Pushing main branch to GitHub...")
    proc = subprocess.run(
        ["git", "push", "-u", remote_url, "main:main", "--force"],
        cwd="A:\\projects\\orbit-security",
        capture_output=True,
        text=True
    )
    # Mask token in output
    out = proc.stdout.replace(token, "[MASKED]")
    err = proc.stderr.replace(token, "[MASKED]")
    print(f"Git Push Returncode: {proc.returncode}")
    print(f"Git Push Stdout: {out}")
    print(f"Git Push Stderr: {err}")

    # 4. Enable GitHub Pages from /docs on main
    pages_payload = {
        "source": {
            "branch": "main",
            "path": "/docs"
        }
    }
    r_pages = httpx.post("https://api.github.com/repos/CmfH009/Orbit-Security/pages", headers=headers, json=pages_payload)
    print(f"Enable GitHub Pages: {r_pages.status_code} - {r_pages.text}")

if __name__ == "__main__":
    main()

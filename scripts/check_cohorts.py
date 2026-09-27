import json
from datetime import datetime
from pathlib import Path

dispatched = json.loads(Path('data/dispatched_campaigns.json').read_text(encoding='utf-8'))
followups = json.loads(Path('data/dispatched_followups.json').read_text(encoding='utf-8'))
now = datetime.now()
print(f"Current Local Time: {now.strftime('%Y-%m-%d %H:%M:%S')}")
print(f"Total in dispatched_campaigns: {len(dispatched)}\n")

for domain, info in dispatched.items():
    disp_time = info.get('dispatched_at')
    dt = datetime.strptime(disp_time, '%Y-%m-%d %H:%M:%S')
    elapsed = (now - dt).total_seconds() / 3600.0
    followed_up = "FOLLOWED_UP" if domain in followups else "PENDING"
    print(f"{domain:28} | Dispatched: {disp_time} | Elapsed: {elapsed:5.1f}h | Status: {followed_up}")

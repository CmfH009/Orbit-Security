import sys, os
from pathlib import Path

# Add src to path
base_dir = Path(r"A:\projects\orbit-security")
sys.path.insert(0, str(base_dir / "src"))

from orbit_security.social_daemon import SocialDaemon

if __name__ == "__main__":
    mode = "auto"
    dry_run = False
    
    if "--desktop" in sys.argv:
        mode = "desktop"
    elif "--headless" in sys.argv:
        mode = "headless"
        
    if "--dry-run" in sys.argv:
        dry_run = True

    print(f"Launching Orbit Social Daemon (driver_mode={mode}, dry_run={dry_run})...")
    daemon = SocialDaemon(
        nominal_interval_seconds=7200,
        dry_run=dry_run,
        driver_mode=mode
    )
    daemon.run_forever()

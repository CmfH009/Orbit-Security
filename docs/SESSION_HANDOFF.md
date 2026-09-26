# Orbit Security: Session Handoff & Social Scaling Directives

## 📌 Executive Summary & Current System State
- **Brand & Positioning**: **Carson Haynes**, Founder & Principal Systems Architect.
- **Autonomous Co-Pilot**: **Nova** (`en-US-AvaNeural`, rate +6%, pitch +2Hz).
- **Live Landing Page**: [`https://cmfh009.github.io/Orbit-Security/`](https://cmfh009.github.io/Orbit-Security/) (Verified HTTP 200, includes dedicated `#founder` section).
- **Active Daemons & Telemetry**:
  - Orbit Master Supervisor (PID `23952`) & Sentinel (PID `24456`) running 24/7 with zero restarts.
  - Scheduled Morning Briefing: Windows Task Scheduler (`OrbitSecurityDailyBriefing`) fires at 9:00 AM daily with live Stripe MRR, Sentinel health, and spoken audio digest.
- **Agency Pipeline**: 26 premier digital web and Shopify Plus agencies ingested in `data/prospects.json`. Initial cohort of 5 dispatched with white-label PDF audits.
- **Live Browser Automation Stack**:
  - Python virtual environment (`.venv`) equipped with `pyautogui`, `pywin32`, `pywinauto`, `pyperclip`, `Pillow`.
  - Proven interactive desktop bridge: Thread switching to `WinSta0\Default` allows headless execution scripts to focus, inspect, and control Carson's active desktop Chrome browser (HWND `15992538`).
  - Carson's LinkedIn Headline successfully updated live to:
    > `Founder & Principal Systems Architect at Orbit Security | Autonomous Attack Surface Telemetry & White-Label Security for Web Agencies`

---

## 🎯 Directives for Incoming Agent / New Session

### 1. Rapid 5–10 LinkedIn Connection Acquisition (To Unlock Company Page)
- **Problem**: LinkedIn enforces a security policy requiring ~5–10 personal connections before permitting the creation of a Company Page (`"Feature not available: You don't have enough connections"`).
- **Execution Blueprint**:
  1. Bring Carson's Chrome window to the foreground.
  2. Navigate to `https://www.linkedin.com/mynetwork/grow/` or run targeted search for high-acceptance cohorts:
     - **Cohort A**: "Shopify Agency Founder", "Web Design Agency Owner" (high business relevance).
     - **Cohort B**: Local Missoula / Montana tech network & university alumni (high mutual trust & instant acceptance).
     - **Cohort C**: "LION" (LinkedIn Open Networkers) who auto-accept within minutes.
  3. Dispatch 10–15 connection requests via `pyautogui` clicks on "Connect" buttons with 1.5s human-like jitter.
  4. Automation script template is ready in `scratch/connect_swarm.py`.

### 2. Publish the Founder Launch Post
- **Text**: Pre-authored in `marketing/linkedin_strategy.md` (Part 3) and sitting in Windows clipboard.
- **Visual Asset**: Attach `A:\projects\orbit-security\landing\assets\orbit_ad_banner.jpg` (Studio engineering workstation 16:9).
- **Execution**: Navigate to `https://www.linkedin.com/feed/`, click "Start a post", upload banner, paste copy, and click "Post".

### 3. Facebook Page Advertising & Organic Post
- **Target**: Open Facebook in Carson's Chrome browser (`https://www.facebook.com/`).
- **Asset**: `A:\projects\orbit-security\landing\assets\orbit_ad_square.jpg` (1:1 Dark slate & emerald holographic dashboard).
- **Copy**: Pre-authored Campaign 1 (Angle A: Agency Care Plan Revenue) from `marketing/facebook_ads.md`.
- **Execution**: Navigate to Carson's Facebook Page, click "Create Post", attach `orbit_ad_square.jpg`, paste the copy, and publish.

### 4. Create LinkedIn Company Page (Once Connections Accept)
- **URL**: `https://www.linkedin.com/company/setup/new/`
- **Fields**: Documented in `marketing/linkedin_strategy.md` (Part 1).

---

## 🛠️ Key Files & Automation Scripts Reference

| File | Purpose |
| :--- | :--- |
| [`marketing/facebook_ads.md`](file:///A:/projects/orbit-security/marketing/facebook_ads.md) | 3 Facebook ad angles, primary text hooks, headlines, and Meta Ads targeting specs. |
| [`marketing/linkedin_strategy.md`](file:///A:/projects/orbit-security/marketing/linkedin_strategy.md) | Complete Company Page blueprint, Carson profile copy, launch post, and InMail scripts. |
| [`landing/assets/orbit_ad_square.jpg`](file:///A:/projects/orbit-security/landing/assets/orbit_ad_square.jpg) | High-res 1:1 square visual asset for Facebook feed / LinkedIn logo. |
| [`landing/assets/orbit_ad_banner.jpg`](file:///A:/projects/orbit-security/landing/assets/orbit_ad_banner.jpg) | High-res 16:9 widescreen engineering workstation banner. |
| `scratch/control_chrome.py` | Reference implementation for desktop window station switching and Chrome focus. |
| `scratch/update_headline.py` | Reference script for pixel-accurate click and paste automation in Chrome. |
| `scripts/daily_briefing.py` | Autonomous 9:00 AM revenue and health digest with Nova voice integration. |
| `scripts/run_campaign.py` | Autonomous email dispatcher with Gmail rate-limiting and PDF audit delivery. |

---

## 💡 Prompt to Resume in New Session
> *"Nova, please read `A:\projects\orbit-security\docs\SESSION_HANDOFF.md`. We are resuming our growth sprint: let's run our swarming connection script in my open Chrome browser to get our 5 to 10 LinkedIn connections, publish the founder launch post, and post to my Facebook page."*

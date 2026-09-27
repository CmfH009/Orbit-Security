"""Orbit Security: SaaS Subdomain Takeover Signatures Database.

Ingested from EdOverflow/can-i-take-over-xyz, Nuclei templates, and curated
cloud provider fingerprints. Provides continuous attack surface intelligence
for agencies monitoring client DNS infrastructure.
"""

from dataclasses import dataclass, field
import json
from typing import List, Optional
import urllib.request


@dataclass
class SaasSignature:
    name: str
    cname_patterns: List[str]
    fingerprints: List[str]
    remediation: str
    nxdomain: bool = False


# Canonical Curated & GitHub can-i-take-over-xyz Signatures
SAAS_TAKEOVER_SIGNATURES: List[SaasSignature] = [
    SaasSignature(
        name="Unbounce",
        cname_patterns=["unbouncepages.com"],
        fingerprints=["The requested URL was not found on this server"],
        remediation="Delete the dangling CNAME DNS record in your DNS manager or re-attach the custom domain in Unbounce.",
    ),
    SaasSignature(
        name="GitHub Pages",
        cname_patterns=["github.io"],
        fingerprints=[
            "There isn't a GitHub Pages site here",
            "For root URLs (like http://example.com/) you must provide an index.html file",
        ],
        remediation="Remove the CNAME pointing to github.io or add the domain to a designated GitHub repository's custom domains settings.",
    ),
    SaasSignature(
        name="AWS S3",
        cname_patterns=["s3.amazonaws.com", "s3-website", ".s3."],
        fingerprints=["NoSuchBucket", "The specified bucket does not exist"],
        remediation="Either create the matching S3 bucket name in your AWS account or remove the orphaned CNAME record.",
    ),
    SaasSignature(
        name="AWS CloudFront",
        cname_patterns=["cloudfront.net"],
        fingerprints=["ERROR: The request could not be satisfied"],
        remediation="Ensure the alternate domain name (CNAME) is configured on an active CloudFront distribution, or remove the DNS record.",
    ),
    SaasSignature(
        name="AWS Elastic Beanstalk",
        cname_patterns=["elasticbeanstalk.com"],
        fingerprints=["NXDOMAIN"],
        remediation="Claim the matching Elastic Beanstalk environment prefix in your AWS region or remove the CNAME record.",
        nxdomain=True,
    ),
    SaasSignature(
        name="Heroku",
        cname_patterns=["herokudns.com", "herokuapp.com"],
        fingerprints=["No such app", "Heroku | No such app"],
        remediation="Remove the Heroku CNAME record from DNS or provision the domain under an active Heroku application.",
    ),
    SaasSignature(
        name="Shopify",
        cname_patterns=["myshopify.com"],
        fingerprints=["Sorry, this shop is currently unavailable", "You'll be able to visit this store soon"],
        remediation="Remove the DNS entry or claim the domain inside your active Shopify store admin panel.",
    ),
    SaasSignature(
        name="Webflow",
        cname_patterns=["proxy.webflow.com", "webflow.io"],
        fingerprints=["The page you are looking for doesn't exist", "The site you are looking for could not be found"],
        remediation="Unlink the DNS mapping or assign the custom domain to a published Webflow project.",
    ),
    SaasSignature(
        name="Zendesk",
        cname_patterns=["zendesk.com"],
        fingerprints=["Help Center Closed", "No help center found"],
        remediation="Remove the CNAME or re-associate it with your active Zendesk Help Center instance.",
    ),
    SaasSignature(
        name="Pantheon",
        cname_patterns=["pantheonsite.io"],
        fingerprints=[
            "The gods are wise, but do not know of the site which you seek",
            "404 error unknown site!",
        ],
        remediation="Delete the CNAME record or bind the hostname to your active Pantheon environment.",
    ),
    SaasSignature(
        name="Netlify",
        cname_patterns=["netlify.app", "netlify.com"],
        fingerprints=["Not Found - Request ID", "Page Not Found - Netlify"],
        remediation="Claim this domain in your Netlify team account or delete the CNAME record immediately.",
    ),
    SaasSignature(
        name="Surge.sh",
        cname_patterns=["surge.sh", "na-west1.surge.sh"],
        fingerprints=["project not found"],
        remediation="Claim the custom domain using `surge --domain` or delete the DNS record.",
    ),
    SaasSignature(
        name="Fly.io",
        cname_patterns=["fly.dev", "shw.io"],
        fingerprints=["Could not find that app", "404 Not Found"],
        remediation="Remove the DNS CNAME record or configure a matching Fly.io certificate and application.",
    ),
    SaasSignature(
        name="HubSpot",
        cname_patterns=["hubspot.net"],
        fingerprints=["Domain not found", "HubSpot page not found"],
        remediation="Remove the CNAME or bind the domain inside HubSpot CMS settings.",
    ),
    SaasSignature(
        name="Ghost",
        cname_patterns=["ghost.io"],
        fingerprints=[
            "The thing you were looking for is no longer here",
            "Fastly error: unknown domain",
            "Site unavailable",
        ],
        remediation="Delete the CNAME pointing to ghost.io or update your publication domain in Ghost.",
    ),
    SaasSignature(
        name="Readme.io",
        cname_patterns=["readme.io"],
        fingerprints=[
            "Project doesnt exist... yet!",
            "Project doesn't exist",
            "The creators of this project are still working on making everything perfect!",
        ],
        remediation="Remove CNAME mapping to Readme.io or claim the project name.",
    ),
    SaasSignature(
        name="UserVoice",
        cname_patterns=["uservoice.com"],
        fingerprints=["This UserVoice instance is no longer active", "This UserVoice subdomain is available"],
        remediation="Remove the UserVoice CNAME record.",
    ),
    SaasSignature(
        name="WordPress.com",
        cname_patterns=["wordpress.com"],
        fingerprints=["Do you want to register", "doesn't exist"],
        remediation="Remove the WordPress.com CNAME or complete custom domain mapping.",
    ),
    SaasSignature(
        name="Bitbucket",
        cname_patterns=["bitbucket.io"],
        fingerprints=["Repository not found"],
        remediation="Remove the CNAME pointing to bitbucket.io or publish a repository under that name.",
    ),
    SaasSignature(
        name="Microsoft Azure",
        cname_patterns=[
            "azurewebsites.net",
            "cloudapp.net",
            "cloudapp.azure.com",
            "blob.core.windows.net",
            "azureedge.net",
            "azurecontainer.io",
            "trafficmanager.net",
        ],
        fingerprints=["NXDOMAIN", "404 Web Site not found"],
        remediation="Ensure custom domain is attached to an active Azure App Service / Traffic Manager or remove the DNS record.",
        nxdomain=True,
    ),
    SaasSignature(
        name="Fastly",
        cname_patterns=["fastly.net"],
        fingerprints=["Fastly error: unknown domain"],
        remediation="Reclaim the Fastly service domain or purge the DNS record.",
    ),
    SaasSignature(
        name="Agile CRM",
        cname_patterns=["agilecrm.com"],
        fingerprints=["Sorry, this page is no longer available."],
        remediation="Remove the Agile CRM CNAME record.",
    ),
    SaasSignature(
        name="Anima",
        cname_patterns=["animaapp.io"],
        fingerprints=["The page you were looking for does not exist."],
        remediation="Remove the Anima CNAME or link the custom domain in your Anima dashboard.",
    ),
    SaasSignature(
        name="Campaign Monitor",
        cname_patterns=["createsend.com"],
        fingerprints=["Trying to access your account?"],
        remediation="Remove the Campaign Monitor CNAME or complete custom domain verification.",
    ),
    SaasSignature(
        name="Cargo Collective",
        cname_patterns=["cargocollective.com"],
        fingerprints=["404 Not Found"],
        remediation="Claim the Cargo Collective URL or delete the orphaned DNS record.",
    ),
    SaasSignature(
        name="Discourse",
        cname_patterns=["trydiscourse.com"],
        fingerprints=["NXDOMAIN"],
        remediation="Remove the Discourse CNAME record.",
        nxdomain=True,
    ),
    SaasSignature(
        name="Gemfury",
        cname_patterns=["furyns.com"],
        fingerprints=["404: This page could not be found."],
        remediation="Remove the Gemfury CNAME record or configure the repository.",
    ),
    SaasSignature(
        name="GetResponse",
        cname_patterns=[".gr8.com", "getresponse.com"],
        fingerprints=["With GetResponse Landing Pages, lead generation has never been easier"],
        remediation="Remove the GetResponse CNAME record.",
    ),
    SaasSignature(
        name="HatenaBlog",
        cname_patterns=["hatenablog.com"],
        fingerprints=["404 Blog is not found"],
        remediation="Remove the HatenaBlog CNAME record.",
    ),
    SaasSignature(
        name="Help Juice",
        cname_patterns=["helpjuice.com"],
        fingerprints=["We could not find what you're looking for."],
        remediation="Delete the Help Juice DNS record or re-attach the knowledge base.",
    ),
    SaasSignature(
        name="Help Scout",
        cname_patterns=["helpscoutdocs.com"],
        fingerprints=["No settings were found for this company:"],
        remediation="Remove the Help Scout CNAME record or configure docs settings.",
    ),
    SaasSignature(
        name="Intercom",
        cname_patterns=["custom.intercom.help"],
        fingerprints=["Uh oh. That page doesn't exist", "Intercom - Help Center Closed"],
        remediation="Delete the Intercom CNAME or reconnect the Intercom Help Center.",
    ),
    SaasSignature(
        name="JetBrains",
        cname_patterns=["youtrack.cloud"],
        fingerprints=["is not a registered InCloud YouTrack"],
        remediation="Remove the JetBrains YouTrack CNAME record.",
    ),
    SaasSignature(
        name="Kinsta",
        cname_patterns=["kinsta.cloud"],
        fingerprints=["No Site Found on Kinsta"],
        remediation="Remove the Kinsta CNAME or re-associate the domain with a Kinsta site.",
    ),
    SaasSignature(
        name="LaunchRock",
        cname_patterns=["launchrock.com"],
        fingerprints=["It looks like you may have taken a wrong turn."],
        remediation="Remove the LaunchRock CNAME or reactivate the campaign.",
    ),
    SaasSignature(
        name="Leadpages",
        cname_patterns=["leadpages.net"],
        fingerprints=["Double check the URL", "Leadpages page not found"],
        remediation="Remove the Leadpages CNAME or attach it to a live funnel.",
    ),
    SaasSignature(
        name="Ngrok",
        cname_patterns=["ngrok.io"],
        fingerprints=["Tunnel .*.ngrok.io not found", "ngrok gateway error"],
        remediation="Remove the ngrok CNAME or bind an active tunnel reservation.",
    ),
    SaasSignature(
        name="SmartJobBoard",
        cname_patterns=["smartjobboard.com"],
        fingerprints=["This job board website is either expired or its domain name is invalid."],
        remediation="Remove the SmartJobBoard CNAME or renew the board subscription.",
    ),
    SaasSignature(
        name="Strikingly",
        cname_patterns=["strikinglydns.com", "s.strikinglydns.com"],
        fingerprints=["PAGE NOT FOUND."],
        remediation="Remove the Strikingly CNAME record or assign the domain to a published site.",
    ),
    SaasSignature(
        name="SurveySparrow",
        cname_patterns=["surveysparrow.com"],
        fingerprints=["Account not found."],
        remediation="Remove the SurveySparrow CNAME record.",
    ),
    SaasSignature(
        name="Uberflip",
        cname_patterns=["read.uberflip.com"],
        fingerprints=["The URL you've accessed does not provide a hub."],
        remediation="Remove the Uberflip CNAME record.",
    ),
    SaasSignature(
        name="UptimeRobot",
        cname_patterns=["stats.uptimerobot.com"],
        fingerprints=["page not found"],
        remediation="Remove the UptimeRobot CNAME or link the public status page.",
    ),
    SaasSignature(
        name="Wishpond",
        cname_patterns=["wishpond.com"],
        fingerprints=["https://www.wishpond.com/404?campaign=true"],
        remediation="Remove the Wishpond CNAME record.",
    ),
    SaasSignature(
        name="Wufoo",
        cname_patterns=["wufoo.com"],
        fingerprints=["Profile not found"],
        remediation="Remove the Wufoo CNAME or configure the custom form URL.",
    ),
    SaasSignature(
        name="Worksites",
        cname_patterns=["worksites.net"],
        fingerprints=["Hello! Sorry, but the website you're looking for doesn't exist."],
        remediation="Remove the Worksites CNAME record.",
    ),
    SaasSignature(
        name="Vercel",
        cname_patterns=["cname.vercel-dns.com", "vercel-dns.com"],
        fingerprints=["The deployment could not be found", "DEPLOYMENT_NOT_FOUND", "404: NOT_FOUND"],
        remediation="Remove the orphaned Vercel CNAME or claim the custom domain in your Vercel project settings.",
    ),
    SaasSignature(
        name="Supabase",
        cname_patterns=["supabase.co"],
        fingerprints=["Project not found", "Project not found or paused"],
        remediation="Delete the dangling CNAME record or associate the custom domain inside your Supabase project settings.",
    ),
    SaasSignature(
        name="Render",
        cname_patterns=["onrender.com"],
        fingerprints=["Not Found", "Render | Not Found"],
        remediation="Remove the dangling CNAME record or configure the custom domain in your Render web service dashboard.",
    ),
    SaasSignature(
        name="Cloudflare Pages",
        cname_patterns=["pages.dev"],
        fingerprints=["Page Not Found", "The requested page could not be found"],
        remediation="Remove the CNAME or bind the custom domain in Cloudflare Pages project settings.",
    ),
    SaasSignature(
        name="Firebase Hosting",
        cname_patterns=["web.app", "firebaseapp.com"],
        fingerprints=["Site Not Found", "Firebase Hosting Setup"],
        remediation="Remove the orphaned Firebase CNAME or connect the domain inside the Firebase Console.",
    ),
    SaasSignature(
        name="BigCommerce",
        cname_patterns=["mybigcommerce.com"],
        fingerprints=["Store not found", "This store is currently unavailable"],
        remediation="Remove the BigCommerce CNAME or claim the domain in your BigCommerce store control panel.",
    ),
    SaasSignature(
        name="Notion",
        cname_patterns=["notion.site"],
        fingerprints=["This page could not be found", "Notion – The all-in-one workspace"],
        remediation="Remove the Notion CNAME record or configure Notion custom domain mapping.",
    ),
]


def sync_github_signatures(
    source_url: str = "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json",
    timeout: float = 6.0,
) -> int:
    """Dynamically syncs and appends new vulnerable signatures from can-i-take-over-xyz.

    Zero-dependency, low-memory implementation designed for Windows environment.
    Returns the total number of active signatures.
    """
    try:
        req = urllib.request.Request(source_url, headers={"User-Agent": "OrbitSecurity-Agent/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        existing_names = {s.name.lower() for s in SAAS_TAKEOVER_SIGNATURES}
        added_count = 0

        for item in data:
            if item.get("status") != "Vulnerable":
                continue

            service = item.get("service", "Unknown")
            if service.lower() in existing_names:
                continue

            cnames = item.get("cname", [])
            fp = item.get("fingerprint", "")
            nx = item.get("nxdomain", False)

            if not cnames:
                continue

            sig = SaasSignature(
                name=service,
                cname_patterns=cnames,
                fingerprints=[fp] if fp else [],
                remediation=f"Remove the dangling CNAME pointing to {cnames[0]} or claim the endpoint on {service}.",
                nxdomain=bool(nx),
            )
            SAAS_TAKEOVER_SIGNATURES.append(sig)
            existing_names.add(service.lower())
            added_count += 1

        return len(SAAS_TAKEOVER_SIGNATURES)
    except Exception:
        return len(SAAS_TAKEOVER_SIGNATURES)

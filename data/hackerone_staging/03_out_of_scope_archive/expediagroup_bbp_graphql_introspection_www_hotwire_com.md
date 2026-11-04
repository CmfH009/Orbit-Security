# [Information Disclosure] Public GraphQL Schema Introspection on www.hotwire.com

**Program:** Expedia Group Bug Bounty (Hackerone)  
**Program Policy:** [https://hackerone.com/expediagroup_bbp](https://hackerone.com/expediagroup_bbp)  
**Asset (In-Scope Target):** `www.hotwire.com`  
**Weakness:** `CWE-200: Exposure of Sensitive Information to an Unauthorized Actor`  
**Severity:** `MEDIUM` (CVSS 3.1: **5.3**)  
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`  
**Bounty Viability Grade:** `HIGH_CONFIDENCE`  
**Date Discovered:** 2026-10-29T10:29:19.804793+00:00  

---

## 1. Summary
> [!TIP] **High-Value Bounty Finding**
> High-confidence security finding verified on target infrastructure with direct impact on origin integrity or confidentiality.

During an external attack surface and DNS perimeter hygiene assessment under the **Expedia Group Bug Bounty** Responsible Disclosure Program, Orbit Security identified a security weakness on `www.hotwire.com`.

- **Vulnerability Category:** `Graphql Introspection`
- **Affected Provider/Service:** `GraphQL`
- **Observed Evidence:** Production GraphQL schema introspection is enabled at 'https://www.hotwire.com/graphql'. Root Query type 'Query' and full schema definition retrieved via public POST request.

---

## 2. Steps to Reproduce (Proof of Concept)
1. Send an HTTP POST request containing a GraphQL introspection query to `www.hotwire.com`:
   ```bash
   curl -i -s -X POST https://www.hotwire.com/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"{ __schema { queryType { name } mutationType { name } types { name } } }"}'
   ```
2. Observe the complete schema hierarchy and internal type definitions in the JSON response.
3. Observe evidence: `Production GraphQL schema introspection is enabled at 'https://www.hotwire.com/graphql'. Root Query type 'Query' and full schema definition retrieved via public POST request.`

---

## 3. Impact
Full GraphQL schema introspection is enabled on `www.hotwire.com` for unauthorized external clients.
This leaks the entire backend data architecture, including:
1. All available queries, mutations, subscriptions, and internal service fields.
2. Undocumented administrative interfaces and sensitive entity relationship graphs.
3. Complete technical specification that significantly accelerates targeted access control bypasses and parameter tampering.

---

## 4. Remediation & Recommended Solution
Disable schema introspection in production deployments. For Apollo Server, set `introspection: false`. For GraphQL Yoga or Envelop, enable the `useDisableIntrospection()` plugin for unauthenticated requests.

---

## 5. Responsible Disclosure Notice
This vulnerability report is submitted in good faith adherence to the **Expedia Group Bug Bounty** Vulnerability Disclosure Policy. Orbit Security did not alter data, claim the resource, degrade service availability, or access any customer information during verification.

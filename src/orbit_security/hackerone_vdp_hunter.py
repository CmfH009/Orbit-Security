"""orbit_security.hackerone_vdp_hunter: HackerOne VDP Recon, Screening & Dispatch Module.

Exposes high-signal VDP screening, structured scope validation, and submission gate
logic with strict zero-trust egress and SSRF controls routed through egress_guard.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Ensure scripts directory is available for underlying engine imports
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from orbit_security.egress_guard import (
    EgressDecision,
    EgressViolationError,
    _is_bogon_or_internal_ip,
    evaluate_egress_target,
    enforce_egress_or_raise,
)
from orbit_security.scanner import is_safe_host, is_safe_ip
from orbit_security.vdp_high_signal_detectors import (
    EXTENDED_SENSITIVE_PATHS,
    check_extended_sensitive_exposures,
    evaluate_cors_response,
    extract_cloud_urls_from_text,
    scan_text_for_high_confidence_secrets,
)
from orbit_security.vdp_recon_sources import (
    discover_multi_source_subdomains,
    extract_explicit_scope_hosts,
    is_program_signal_eligible,
    load_non_empty_ct_cache,
    purge_empty_ct_cache_entries,
    save_non_empty_ct_cache,
)

from hunt_hackerone_vdps import (
    DEFAULT_CANDIDATES_PATH,
    DEFAULT_MANIFEST_PATH,
    DEFAULT_PROGRAMS_PATH,
    DEFAULT_PROBE_USER_AGENT,
    DEFAULT_RESEARCHER_HANDLE,
    DEFAULT_VDP_CT_CACHE_PATH,
    DEFAULT_VDP_READY_DIR,
    PRIORITY_SUBDOMAIN_TOKENS,
    QualityGateResult,
    SENSITIVE_EXPOSURE_PATHS,
    VdpFinding,
    VdpProgram,
    _SafeVdpRedirectHandler,
    build_auth_header,
    check_exposed_config_or_git,
    check_open_bucket_listing,
    check_takeover_claimability,
    discover_passive_subdomains,
    evaluate_submission_quality_gate,
    fetch_http_sample,
    fetch_paginated_h1,
    fetch_program_graphql_gates,
    fetch_program_kyc_status_graphql,
    filter_kyc_free_vdp_programs,
    is_bucket_listing_non_public,
    is_duplicate_finding,
    main,
    match_structured_scope,
    render_vdp_dossier,
    resolve_dns_cname_chain_guarded,
    resolve_dns_doh,
    run_vdp_hunt,
    screen_host_non_destructively,
    select_weakness_id,
    submit_vdp_finding,
)

__all__ = [
    "DEFAULT_CANDIDATES_PATH",
    "DEFAULT_MANIFEST_PATH",
    "DEFAULT_PROGRAMS_PATH",
    "DEFAULT_PROBE_USER_AGENT",
    "DEFAULT_RESEARCHER_HANDLE",
    "DEFAULT_VDP_CT_CACHE_PATH",
    "DEFAULT_VDP_READY_DIR",
    "EXTENDED_SENSITIVE_PATHS",
    "PRIORITY_SUBDOMAIN_TOKENS",
    "QualityGateResult",
    "SENSITIVE_EXPOSURE_PATHS",
    "VdpFinding",
    "VdpProgram",
    "_SafeVdpRedirectHandler",
    "_is_bogon_or_internal_ip",
    "build_auth_header",
    "check_exposed_config_or_git",
    "check_extended_sensitive_exposures",
    "check_open_bucket_listing",
    "check_takeover_claimability",
    "discover_multi_source_subdomains",
    "discover_passive_subdomains",
    "evaluate_cors_response",
    "evaluate_egress_target",
    "evaluate_submission_quality_gate",
    "extract_cloud_urls_from_text",
    "extract_explicit_scope_hosts",
    "fetch_http_sample",
    "fetch_paginated_h1",
    "fetch_program_graphql_gates",
    "fetch_program_kyc_status_graphql",
    "filter_kyc_free_vdp_programs",
    "is_bucket_listing_non_public",
    "is_duplicate_finding",
    "is_program_signal_eligible",
    "is_safe_host",
    "is_safe_ip",
    "main",
    "match_structured_scope",
    "purge_empty_ct_cache_entries",
    "render_vdp_dossier",
    "resolve_dns_cname_chain_guarded",
    "resolve_dns_doh",
    "run_vdp_hunt",
    "save_non_empty_ct_cache",
    "scan_text_for_high_confidence_secrets",
    "screen_host_non_destructively",
    "select_weakness_id",
    "submit_vdp_finding",
]

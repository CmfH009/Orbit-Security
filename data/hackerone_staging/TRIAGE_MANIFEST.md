# HackerOne Staging Triage Manifest

Generated on 2026-11-03.

## 1. High Potential Candidates (Needs Session/PII Verification)
These have confirmed CORS arbitrary origin reflection with `Access-Control-Allow-Credentials: true` or open storage listings. Before submitting to HackerOne, test an authenticated endpoint with real cookies to capture proof of user data exposure.

| File | Reason / Target |
| :--- | :--- |
| `mercadolibre_cors_arbitrary_origin_with_credentials_buyingflow_mercadolibre_com_co.md` | CORS credentials reflected - requires authenticated endpoint check for private data |
| `mercadolibre_cors_arbitrary_origin_with_credentials_buyingflow_mercadolibre_com_mx.md` | CORS credentials reflected - requires authenticated endpoint check for private data |
| `mercadolibre_cors_arbitrary_origin_with_credentials_buyingflow_mercadolibre_com_pe.md` | CORS credentials reflected - requires authenticated endpoint check for private data |
| `mercadolibre_cors_arbitrary_origin_with_credentials_images_mercadolibre_com_co.md` | CORS credentials reflected - requires authenticated endpoint check for private data |
| `mercadolibre_cors_arbitrary_origin_with_credentials_lhstage_mercadolibre_com_ar.md` | CORS credentials reflected - requires authenticated endpoint check for private data |
| `mercadolibre_cors_arbitrary_origin_with_credentials_realtime-test_mercadolibre_com_mx.md` | CORS credentials reflected - requires authenticated endpoint check for private data |
| `mercadolibre_cors_arbitrary_origin_with_credentials_test-vendedores_mercadolibre_cl.md` | CORS credentials reflected - requires authenticated endpoint check for private data |
| `mercadolibre_cors_arbitrary_origin_with_credentials_test-vendedores_mercadolibre_com_co.md` | CORS credentials reflected - requires authenticated endpoint check for private data |
| `mercadolibre_cors_arbitrary_origin_with_credentials_tucarro_com_co.md` | CORS credentials reflected - requires authenticated endpoint check for private data |
| `playtika_cors_arbitrary_origin_with_credentials_slotomania_com.md` | CORS credentials reflected - requires authenticated endpoint check for private data |
| `spotify_open_cloud_bucket_cdn_byspotify_com.md` | Spotify CDN bucket listing - requires inspection for non-public assets |
| `superbet_cors_arbitrary_origin_with_credentials_apps_stage_napoleoncasino_be.md` | CORS credentials reflected - requires authenticated endpoint check for private data |
| `superbet_cors_arbitrary_origin_with_credentials_apps_stage_napoleonsports_be.md` | CORS credentials reflected - requires authenticated endpoint check for private data |
| `uber_cors_arbitrary_origin_with_credentials_fpbi8c1t_ubereats_com.md` | CORS credentials reflected - requires authenticated endpoint check for private data |
| `uber_cors_arbitrary_origin_with_credentials_fpfcpn2u_ubereats_com.md` | CORS credentials reflected - requires authenticated endpoint check for private data |
| `xiaomi_cors_arbitrary_origin_with_credentials_airstarfinance_net.md` | CORS credentials reflected - requires authenticated endpoint check for private data |
| `xiaomi_cors_arbitrary_origin_with_credentials_mijiayoupin_com.md` | CORS credentials reflected - requires authenticated endpoint check for private data |
| `xiaomi_cors_arbitrary_origin_with_credentials_wali_com.md` | CORS credentials reflected - requires authenticated endpoint check for private data |
| `xiaomi_cors_arbitrary_origin_with_credentials_www_airstarfinance_net.md` | CORS credentials reflected - requires authenticated endpoint check for private data |
| `xiaomi_cors_arbitrary_origin_with_credentials_xiaomiyoupin_com.md` | CORS credentials reflected - requires authenticated endpoint check for private data |
| `xiaomi_cors_arbitrary_origin_with_credentials_youpin_cn.md` | CORS credentials reflected - requires authenticated endpoint check for private data |

## 2. Archived / Out of Scope (DO NOT SUBMIT)
Submitting these will result in immediate N/A closures and HackerOne reputation deductions (-7 reputation per N/A).

| File | Reason for Exclusion |
| :--- | :--- |
| `elastic_mail_spoofing_elasticacademy_com.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `elastic_mail_spoofing_elasticps_co.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `elastic_mail_spoofing_elasticsearch_com.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `elastic_mail_spoofing_elasticsearch_org.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `elastic_mail_spoofing_insight_io.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `elastic_mail_spoofing_prelert_com.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `eternal_mail_spoofing_edition_in.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `eternal_mail_spoofing_eternal_com.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `eternal_mail_spoofing_insider_in.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `eternal_mail_spoofing_runnr_in.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `eternal_mail_spoofing_ticketnew_com.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `eternal_mail_spoofing_tktnew_com.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `eternal_mail_spoofing_zdev_net.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `expediagroup_bbp_graphql_introspection_www_hotwire_com.md` | GraphQL schema introspection on public API - documented vendor behavior |
| `expediagroup_bbp_mail_spoofing_bookabach_co_nz.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `expediagroup_bbp_mail_spoofing_expedia-aarp_com.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `expediagroup_bbp_mail_spoofing_flights_com.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `expediagroup_bbp_mail_spoofing_lastminute_co_nz.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `flutteruki_mail_spoofing_metrocompetitions_com.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `flutteruki_mail_spoofing_platformservices_io.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `flutteruki_mail_spoofing_ppb_com.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `flutteruki_mail_spoofing_ppbdev_com.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `flutteruki_mail_spoofing_rafflee_co_uk.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `gitlab_cloud_storage_takeover_assets_gitlab_com.md` | No dangling CNAME (Cloudflare/GCP proxy false positive) |
| `gitlab_graphql_introspection_gitlab_com.md` | GraphQL schema introspection on public API - documented vendor behavior |
| `khealth_cloud_storage_takeover_cdn_khealth-test_com.md` | No dangling CNAME (Cloudflare/GCP proxy false positive) |
| `khealth_mail_spoofing_hhc247_org.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `khealth_mail_spoofing_khealth_com.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `mercadolibre_mail_spoofing_furycloud_io.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `mercadolibre_mail_spoofing_mlstatic_com.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `mercadolibre_mail_spoofing_mpago_la.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `mercadolibre_mail_spoofing_portalinmobiliario_cl.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `mercadolibre_mail_spoofing_portalinmobiliario_com.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `mercadolibre_mail_spoofing_tucarro_com.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `playtika_mail_spoofing_bestfiends_com.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `shopify_graphql_introspection_media_myshopify_com.md` | GraphQL schema introspection on public API - documented vendor behavior |
| `superbet_mail_spoofing_luckydays_ca.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `superbet_mail_spoofing_luckydays_com.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `superbet_mail_spoofing_spinaway_com.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `superbet_mail_spoofing_superbet_gr.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `superbet_mail_spoofing_superbet_pl.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `superbet_mail_spoofing_superbet_ro.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `trip_com_mail_spoofing_tyo-masters_co_jp.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `xiaomi_mail_spoofing_duokan_com.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `xiaomi_mail_spoofing_miui_com.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `xiaomi_mail_spoofing_wali_com.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `xiaomi_mail_spoofing_xiaomi_net.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `xiaomi_mail_spoofing_xunkids_com.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |
| `xiaomi_mail_spoofing_zmifi_com.md` | Missing DMARC/SPF - universally excluded from HackerOne bounties |

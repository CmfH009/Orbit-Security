# Terraform Cloudflare SPF Fix for alley_interactive.com
resource "cloudflare_record" "spf_remediation" {
  zone_id = "example_zone_id"
  name    = "@"
  type    = "TXT"
  content = "v=spf1 ip4:192.0.2.1 ip4:198.51.100.2 -all"
  ttl     = 300
  comment = "Remediated by Orbit Security (RFC 7208 PermError flattening)"
}
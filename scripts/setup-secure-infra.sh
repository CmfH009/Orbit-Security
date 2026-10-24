#!/usr/bin/env bash
# orbit-security/scripts/setup-secure-infra.sh
# One-time secure infrastructure setup for Orbit Security API
# Run once: chmod +x setup-secure-infra.sh && ./setup-secure-infra.sh

set -euo pipefail

PROJECT_ID="${GCP_PROJECT_ID:-}"
REGION="${GCP_REGION:-us-central1}"
SERVICE_ACCOUNT="orbit-api-sa"
VPC_CONNECTOR="orbit-vpc-connector"
WAF_POLICY="orbit-waf"
ARTIFACT_REPO="orbit-repo"
ALERT_EMAIL="${ALERT_EMAIL:-}"

if [[ -z "$PROJECT_ID" ]]; then
  echo "ERROR: GCP_PROJECT_ID environment variable required"
  exit 1
fi

echo "🔐 Setting up secure infrastructure for project: $PROJECT_ID"

# Enable required APIs
echo "📦 Enabling required APIs..."
gcloud services enable \
  run.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  containerscanning.googleapis.com \
  vpcaccess.googleapis.com \
  compute.googleapis.com \
  monitoring.googleapis.com \
  logging.googleapis.com \
  --project="$PROJECT_ID"

# Create Artifact Registry with vulnerability scanning
echo "📦 Creating Artifact Registry..."
gcloud artifacts repositories create "$ARTIFACT_REPO" \
  --repository-format=docker \
  --location="$REGION" \
  --description="Orbit Security hardened container images" \
  --project="$PROJECT_ID" 2>/dev/null || echo "Repository exists"

# Create Service Account with MINIMAL permissions
echo "👤 Creating service account..."
gcloud iam service-accounts create "$SERVICE_ACCOUNT" \
  --display-name="Orbit Security API Runtime" \
  --description="Minimal permissions for Orbit Security API - no storage, no build access" \
  --project="$PROJECT_ID" 2>/dev/null || echo "Service account exists"

# Grant ONLY necessary roles
echo "🔑 Granting minimal IAM roles..."
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${SERVICE_ACCOUNT}@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/logging.logWriter" \
  --condition=None

gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${SERVICE_ACCOUNT}@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/monitoring.metricWriter" \
  --condition=None

# Create VPC Connector for private networking
echo "🌐 Creating VPC Connector..."
gcloud compute networks vpc-access connectors create "$VPC_CONNECTOR" \
  --region="$REGION" \
  --network=default \
  --range=10.8.0.0/28 \
  --min-instances=0 \
  --max-instances=3 \
  --project="$PROJECT_ID" 2>/dev/null || echo "VPC connector exists"

# Create Cloud Armor WAF Policy
echo "🛡️ Creating Cloud Armor WAF..."
gcloud compute security-policies create "$WAF_POLICY" \
  --description="Orbit Security API WAF - SQLi, XSS, RCE, Rate Limiting" \
  --project="$PROJECT_ID" 2>/dev/null || echo "WAF policy exists"

# Rule 1000: Block SQLi, XSS, RCE
gcloud compute security-policies rules create 1000 \
  --security-policy="$WAF_POLICY" \
  --expression="evaluatePreconfiguredExpr('sqli-stable') || evaluatePreconfiguredExpr('xss-stable') || evaluatePreconfiguredExpr('rce-stable')" \
  --action=deny-403 \
  --project="$PROJECT_ID" 2>/dev/null || \
gcloud compute security-policies rules update 1000 \
  --security-policy="$WAF_POLICY" \
  --expression="evaluatePreconfiguredExpr('sqli-stable') || evaluatePreconfiguredExpr('xss-stable') || evaluatePreconfiguredExpr('rce-stable')" \
  --action=deny-403 \
  --project="$PROJECT_ID"

# Rule 2000: Rate limiting - 100 req/min per IP
gcloud compute security-policies rules create 2000 \
  --security-policy="$WAF_POLICY" \
  --expression="true" \
  --action=rate-based-ban \
  --rate-limit-threshold-count=100 \
  --rate-limit-threshold-interval-sec=60 \
  --ban-duration-sec=300 \
  --project="$PROJECT_ID" 2>/dev/null || \
gcloud compute security-policies rules update 2000 \
  --security-policy="$WAF_POLICY" \
  --expression="true" \
  --action=rate-based-ban \
  --rate-limit-threshold-count=100 \
  --rate-limit-threshold-interval-sec=60 \
  --ban-duration-sec=300 \
  --project="$PROJECT_ID"

# ==========================================
# Cloud Monitoring Alerting Policies
# ==========================================
echo "📊 Creating Cloud Monitoring alerting policies..."

# Notification channel (email) - create if not exists
NOTIFICATION_CHANNEL=$(gcloud alpha monitoring channels list \
  --filter="displayName='Orbit Security Alerts'" \
  --format="value(name)" --project="$PROJECT_ID" 2>/dev/null | head -1)

if [[ -z "$NOTIFICATION_CHANNEL" ]]; then
  echo "📧 Creating notification channel..."
  NOTIFICATION_CHANNEL=$(gcloud alpha monitoring channels create \
    --display-name="Orbit Security Alerts" \
    --type=email \
    --channel-labels=email_address="${ALERT_EMAIL:-admin@$(gcloud config get-value project)}" \
    --project="$PROJECT_ID" \
    --format="value(name)")
else
  echo "📧 Using existing notification channel: $NOTIFICATION_CHANNEL"
fi

# Alert 1: Service Down (Uptime Check Failure)
echo "🚨 Creating uptime check + alert for /api/health..."
UPTIME_CHECK=$(gcloud monitoring uptime-check-configs list \
  --filter="displayName='Orbit API Health'" \
  --format="value(name)" --project="$PROJECT_ID" 2>/dev/null | head -1)

if [[ -z "$UPTIME_CHECK" ]]; then
  gcloud monitoring uptime-check-configs create \
    --display-name="Orbit API Health" \
    --hostname="$(gcloud run services describe orbit-security-api --region=$REGION --format='value(status.url)' --project=$PROJECT_ID | sed 's|https://||' | sed 's|/.*||')" \
    --path="/api/health" \
    --port=443 \
    --check-interval=60s \
    --timeout=10s \
    --project="$PROJECT_ID" 2>/dev/null || echo "Uptime check exists"
fi

# Alert Policy 1: Service Down
cat > /tmp/alert-service-down.yaml <<EOF
displayName: "Orbit API - Service Down"
combiner: OR
conditions:
  - displayName: "Uptime check failed"
    conditionThreshold:
      filter: 'metric.type="monitoring.googleapis.com/uptime_check/check_passed" AND resource.type="uptime_url"'
      comparison: COMPARISON_LT
      thresholdValue: 1
      duration: "60s"
      aggregations:
        - alignmentPeriod: "60s"
          perSeriesAligner: ALIGN_FRACTION_TRUE
    conditionAbsent:
      filter: 'metric.type="monitoring.googleapis.com/uptime_check/check_passed" AND resource.type="uptime_url"'
      duration: "120s"
      aggregations:
        - alignmentPeriod: "60s"
          perSeriesAligner: ALIGN_FRACTION_TRUE
EOF

gcloud alpha monitoring policies create --policy-from-file=/tmp/alert-service-down.yaml \
  --notification-channels="$NOTIFICATION_CHANNEL" \
  --project="$PROJECT_ID" 2>/dev/null || echo "Alert exists"

# Alert Policy 2: High Error Rate (5xx)
cat > /tmp/alert-high-errors.yaml <<EOF
displayName: "Orbit API - High Error Rate (5xx)"
combiner: OR
conditions:
  - displayName: "5xx error rate > 5%"
    conditionThreshold:
      filter: 'metric.type="run.googleapis.com/request_count" AND resource.type="cloud_run_revision" AND metric.labels.response_code_class="5xx"'
      comparison: COMPARISON_GT
      thresholdValue: 0.05
      duration: "300s"
      aggregations:
        - alignmentPeriod: "60s"
          perSeriesAligner: ALIGN_RATE
          crossSeriesReducer: REDUCE_SUM
          groupByFields: ["resource.label.service_name", "resource.label.location"]
EOF

gcloud alpha monitoring policies create --policy-from-file=/tmp/alert-high-errors.yaml \
  --notification-channels="$NOTIFICATION_CHANNEL" \
  --project="$PROJECT_ID" 2>/dev/null || echo "Alert exists"

# Alert Policy 3: High Latency (p99 > 2s)
cat > /tmp/alert-high-latency.yaml <<EOF
displayName: "Orbit API - High Latency (p99 > 2s)"
combiner: OR
conditions:
  - displayName: "Request latency p99 > 2s"
    conditionThreshold:
      filter: 'metric.type="run.googleapis.com/request_latencies" AND resource.type="cloud_run_revision"'
      comparison: COMPARISON_GT
      thresholdValue: 2.0
      duration: "300s"
      aggregations:
        - alignmentPeriod: "60s"
          perSeriesAligner: ALIGN_PERCENTILE_99
          crossSeriesReducer: REDUCE_MEAN
          groupByFields: ["resource.label.service_name", "resource.label.location"]
EOF

gcloud alpha monitoring policies create --policy-from-file=/tmp/alert-high-latency.yaml \
  --notification-channels="$NOTIFICATION_CHANNEL" \
  --project="$PROJECT_ID" 2>/dev/null || echo "Alert exists"

# Alert Policy 4: Scale Events (Instances > 2)
cat > /tmp/alert-scale-events.yaml <<EOF
displayName: "Orbit API - Scale Event (Instances > 2)"
combiner: OR
conditions:
  - displayName: "Instance count > 2"
    conditionThreshold:
      filter: 'metric.type="run.googleapis.com/container/instance_count" AND resource.type="cloud_run_revision"'
      comparison: COMPARISON_GT
      thresholdValue: 2
      duration: "180s"
      aggregations:
        - alignmentPeriod: "60s"
          perSeriesAligner: ALIGN_MAX
          crossSeriesReducer: REDUCE_MAX
          groupByFields: ["resource.label.service_name", "resource.label.location"]
EOF

gcloud alpha monitoring policies create --policy-from-file=/tmp/alert-scale-events.yaml \
  --notification-channels="$NOTIFICATION_CHANNEL" \
  --project="$PROJECT_ID" 2>/dev/null || echo "Alert exists"

# Alert Policy 5: Rate Limit Triggered (Cloud Armor)
cat > /tmp/alert-rate-limit.yaml <<EOF
displayName: "Orbit API - Rate Limit Triggered"
combiner: OR
conditions:
  - displayName: "Rate limit ban active"
    conditionThreshold:
      filter: 'metric.type="cloudarmor.googleapis.com/rate_limit_ban" AND resource.type="cloud_armor_security_policy"'
      comparison: COMPARISON_GT
      thresholdValue: 0
      duration: "60s"
      aggregations:
        - alignmentPeriod: "60s"
          perSeriesAligner: ALIGN_MAX
          crossSeriesReducer: REDUCE_SUM
EOF

gcloud alpha monitoring policies create --policy-from-file=/tmp/alert-rate-limit.yaml \
  --notification-channels="$NOTIFICATION_CHANNEL" \
  --project="$PROJECT_ID" 2>/dev/null || echo "Alert exists"

# Alert Policy 6: CPU/Memory High
cat > /tmp/alert-resources.yaml <<EOF
displayName: "Orbit API - High Resource Usage"
combiner: OR
conditions:
  - displayName: "CPU utilization > 80%"
    conditionThreshold:
      filter: 'metric.type="run.googleapis.com/container/cpu/utilizations" AND resource.type="cloud_run_revision"'
      comparison: COMPARISON_GT
      thresholdValue: 0.8
      duration: "300s"
      aggregations:
        - alignmentPeriod: "60s"
          perSeriesAligner: ALIGN_MEAN
          crossSeriesReducer: REDUCE_MEAN
          groupByFields: ["resource.label.service_name", "resource.label.location"]
  - displayName: "Memory utilization > 80%"
    conditionThreshold:
      filter: 'metric.type="run.googleapis.com/container/memory/utilizations" AND resource.type="cloud_run_revision"'
      comparison: COMPARISON_GT
      thresholdValue: 0.8
      duration: "300s"
      aggregations:
        - alignmentPeriod: "60s"
          perSeriesAligner: ALIGN_MEAN
          crossSeriesReducer: REDUCE_MEAN
          groupByFields: ["resource.label.service_name", "resource.label.location"]
EOF

gcloud alpha monitoring policies create --policy-from-file=/tmp/alert-resources.yaml \
  --notification-channels="$NOTIFICATION_CHANNEL" \
  --project="$PROJECT_ID" 2>/dev/null || echo "Alert exists"

# Cleanup temp files
rm -f /tmp/alert-*.yaml

echo ""
echo "✅ Monitoring alerts created!"
echo ""
echo "📋 Next steps:"
echo "1. Add these GitHub Secrets to your repo:"
echo "   - GCP_PROJECT_ID: $PROJECT_ID"
echo "   - GCP_WIF_PROVIDER: projects/\$(gcloud projects describe \$PROJECT_ID --format='value(projectNumber)')/locations/global/workloadIdentityPools/github/providers/github"
echo "   - GCP_SERVICE_ACCOUNT: github-actions@${PROJECT_ID}.iam.gserviceaccount.com"
echo ""
echo "2. Create GitHub Actions OIDC provider:"
echo "   gcloud iam workload-identity-pools create github --location=global --display-name=\"GitHub Actions\" --project=$PROJECT_ID"
echo "   gcloud iam workload-identity-pools providers create-oidc github \\"
echo "     --workload-identity-pool=github \\"
echo "     --location=global \\"
echo "     --issuer-uri=https://token.actions.githubusercontent.com \\"
echo "     --attribute-mapping=\"google.subject=assertion.sub,attribute.actor=assertion.actor,attribute.repository=assertion.repository\" \\"
echo "     --project=$PROJECT_ID"
echo ""
echo "3. Grant GitHub Actions impersonation:"
echo "   gcloud iam service-accounts add-iam-policy-binding \\"
echo "     github-actions@${PROJECT_ID}.iam.gserviceaccount.com \\"
echo "     --role=roles/iam.workloadIdentityUser \\"
echo "     --member=\"principalSet://iam.googleapis.com/projects/\$(gcloud projects describe \$PROJECT_ID --format='value(projectNumber)')/locations/global/workloadIdentityPools/github/attribute.repository/$(git config --get remote.origin.url | sed 's/.*github.com[:/]\(.*\)\.git/\1/')\" \\"
echo "     --project=$PROJECT_ID"
echo ""
echo "4. Deploy on push to main:"
echo "   git push origin main"
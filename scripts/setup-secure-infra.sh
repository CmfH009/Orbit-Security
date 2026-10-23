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

echo ""
echo "✅ Infrastructure setup complete!"
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
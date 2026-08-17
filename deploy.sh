#!/usr/bin/env bash
# Copyright 2026 Google LLC
#
# Deploy Google SecOps MCP Server using Streamable HTTP (Current Standard) to Cloud Run
# Includes Step for Custom Environment Variables & .env file support.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=================================================================="
echo "🚀 Google SecOps MCP Server Deployment (Streamable HTTP Standard)"
echo "=================================================================="

# ==============================================================================
# STEP 1: Load and Process Custom Variables
# ==============================================================================
echo ""
echo "🔧 [Step 1/5] Configuring Environment & Custom Variables..."

# 1.1 Auto-load .env file if present
ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/.env}"
if [[ -f "$ENV_FILE" ]]; then
    echo "  📄 Loading configuration from $ENV_FILE"
    set -o allexport
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +o allexport
else
    echo "  ℹ️  No .env file found at $ENV_FILE. Using environment defaults."
    echo "     (Tip: You can copy .env.example to .env to persist custom variables)"
fi

# 1.2 Resolve Core Deployment Variables with defaults
DEPLOY_PROJECT_ID="${PROJECT_ID:-gemini-entreprise-494918}"
REGION="${REGION:-us-central1}"
SERVICE_NAME="${SECOPS_SERVICE_NAME:-${SERVICE_NAME:-secops-mcp-server}}"
RUNNER_SA="${RUNNER_SA:-google-security-agent-runner@gemini-entreprise-494918.iam.gserviceaccount.com}"

# 1.3 Resolve Chronicle / SecOps Variables
CHRONICLE_PROJECT_ID="${CHRONICLE_PROJECT_ID:-$DEPLOY_PROJECT_ID}"
CHRONICLE_CUSTOMER_ID="${CHRONICLE_CUSTOMER_ID:-${CHRONICLE_INSTANCE_ID:-}}"
CHRONICLE_REGION="${CHRONICLE_REGION:-us}"
LOG_LEVEL="${LOG_LEVEL:-INFO}"

# 1.4 Assemble Standard Environment Variables for Cloud Run
ENV_VARS_MAP=(
    "CHRONICLE_PROJECT_ID=$CHRONICLE_PROJECT_ID"
    "CHRONICLE_CUSTOMER_ID=$CHRONICLE_CUSTOMER_ID"
    "CHRONICLE_REGION=$CHRONICLE_REGION"
    "LOG_LEVEL=$LOG_LEVEL"
)

# 1.5 Append Optional Custom Variables (e.g., SECOPS_SA_PATH, CUSTOM_ENV_VARS)
if [[ -n "$SECOPS_SA_PATH" ]]; then
    ENV_VARS_MAP+=("SECOPS_SA_PATH=$SECOPS_SA_PATH")
fi

if [[ -n "$CUSTOM_ENV_VARS" ]]; then
    echo "  ➕ Adding user-defined custom variables from CUSTOM_ENV_VARS: $CUSTOM_ENV_VARS"
    IFS=',' read -ra ADDR <<< "$CUSTOM_ENV_VARS"
    for var in "${ADDR[@]}"; do
        trimmed_var="$(echo "$var" | xargs)"
        if [[ -n "$trimmed_var" ]]; then
            ENV_VARS_MAP+=("$trimmed_var")
        fi
    done
fi

# Join all environment variables into a single comma-separated string
ENV_VARS_STRING=$(IFS=,; echo "${ENV_VARS_MAP[*]}")

# 1.6 Display Configuration Summary
echo ""
echo "  📋 Variable Summary:"
echo "     • Cloud Run Hosting Project : $DEPLOY_PROJECT_ID"
echo "     • Region                    : $REGION"
echo "     • Service Name              : $SERVICE_NAME"
echo "     • SecOps Project ID         : $CHRONICLE_PROJECT_ID"
echo "     • SecOps Customer ID        : ${CHRONICLE_CUSTOMER_ID:-<simulated fallback>}"
echo "     • SecOps Region             : $CHRONICLE_REGION"
echo "     • Log Level                 : $LOG_LEVEL"
echo "     • Injected Env Variables    : $ENV_VARS_STRING"
echo ""

# ==============================================================================
# STEP 2: Enable Google Cloud Services
# ==============================================================================
echo "☁️  [Step 2/5] Enabling required Google Cloud APIs..."
gcloud services enable run.googleapis.com cloudbuild.googleapis.com --project="$DEPLOY_PROJECT_ID"
gcloud services enable chronicle.googleapis.com --project="$CHRONICLE_PROJECT_ID" 2>/dev/null || true

# ==============================================================================
# STEP 3: Deploy Cloud Run Service
# ==============================================================================
echo "🚢 [Step 3/5] Deploying Cloud Run Service with Streamable HTTP transport..."
gcloud run deploy "$SERVICE_NAME" \
    --source="$SCRIPT_DIR" \
    --project="$DEPLOY_PROJECT_ID" \
    --region="$REGION" \
    --platform="managed" \
    --ingress="all" \
    --no-allow-unauthenticated \
    --port=8080 \
    --timeout=300 \
    --min-instances=1 \
    --max-instances=5 \
    --session-affinity \
    --set-env-vars "$ENV_VARS_STRING"

# ==============================================================================
# STEP 4: Grant IAM Invoker Permissions
# ==============================================================================
echo "🔐 [Step 4/5] Configuring IAM Policy Bindings (roles/run.invoker)..."

# Grant to Agent Runner Service Account
echo "  • Granting roles/run.invoker to runner service account: $RUNNER_SA"
gcloud run services add-iam-policy-binding "$SERVICE_NAME" \
    --project="$DEPLOY_PROJECT_ID" \
    --region="$REGION" \
    --member="serviceAccount:$RUNNER_SA" \
    --role="roles/run.invoker" || true

# Grant to Active Authenticated User for testing
ACTIVE_USER=$(gcloud config get-value account 2>/dev/null || echo "")
if [[ -n "$ACTIVE_USER" ]]; then
    echo "  • Granting roles/run.invoker to active user: $ACTIVE_USER"
    gcloud run services add-iam-policy-binding "$SERVICE_NAME" \
        --project="$DEPLOY_PROJECT_ID" \
        --region="$REGION" \
        --member="user:$ACTIVE_USER" \
        --role="roles/run.invoker" || true
fi

# ==============================================================================
# STEP 5: Verification and Endpoint Resolution
# ==============================================================================
echo ""
echo "✅ [Step 5/5] Deployment Successful!"
SERVICE_URL=$(gcloud run services describe "$SERVICE_NAME" --region="$REGION" --project="$DEPLOY_PROJECT_ID" --format="value(status.url)")
STREAMABLE_HTTP_URL="${SERVICE_URL}/mcp"

echo ""
echo "=================================================================="
echo "🎉 Google SecOps MCP Server Deployed Successfully!"
echo " Base URL:                 $SERVICE_URL"
echo " Streamable HTTP Endpoint: $STREAMABLE_HTTP_URL"
echo " Health Probe:             $SERVICE_URL/healthz"
echo ""
echo "👉 Connect your Security Agent:"
echo "   export SECOPS_MCP_URL=\"$STREAMABLE_HTTP_URL\""
echo ""
echo "🧪 Local testing via authenticated gcloud proxy:"
echo "   gcloud run services proxy $SERVICE_NAME --region=$REGION --port=8080"
echo "   # Target http://localhost:8080/mcp"
echo "=================================================================="

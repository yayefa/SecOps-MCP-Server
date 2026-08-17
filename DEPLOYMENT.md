# 🚀 Google SecOps (Chronicle) MCP Server Deployment Guide

This guide details step-by-step instructions for deploying and validating the **Google Chronicle Security Operations (SecOps) MCP Server** on Google Cloud Run using the **Streamable HTTP transport standard (`/mcp`)** with complete enterprise IAM authentication.

---

## 📋 Architecture & Standards

- **Protocol**: Model Context Protocol (MCP) Streamable HTTP Transport (`2024-11-05`)
- **MCP Endpoint**: `https://<YOUR-CLOUD-RUN-URL>/mcp`
- **Fallback Endpoints**: Zero-redirect `/mcp/`, `/healthz`, `/health`, `/status`
- **Tool Suite**: 29 Official Google SecOps Tools:
  - **Investigation**: `get_security_alerts`, `get_alert_details`, `get_asset_timeline`, `get_domain_timeline`, `get_user_timeline`, `search_security_events`, `search_iocs`
  - **Detection / YARA-L Rules**: `list_detection_rules`, `get_detection_rule`, `create_detection_rule`, `update_detection_rule`, `enable_detection_rule`, `disable_detection_rule`, `verify_rule_syntax`, `list_rule_executions`
  - **Ingestion & Data Tables**: `get_ingestion_metrics`, `create_data_table`, `list_data_tables`, `query_data_table`, `insert_data_table_rows`
  - **Reference Lists & Parsers**: `list_reference_lists`, `get_reference_list`, `update_reference_list`, `list_log_parsers`, `get_parser_details`, `submit_parser_extension`
  - **SecOps Context**: `get_entity_summary`, `get_curated_detections`
- **Hosting**: Google Cloud Run (Serverless Container with Managed HTTPS)
- **Security**: Google Cloud IAM OAuth2 / ID Tokens (`roles/run.invoker`)

---

## ⚙️ Environment Variables & Configuration

Configuration is managed via `.env` (copied from `.env.example`):

| Variable | Required | Description | Example / Placeholder | Source |
| :--- | :---: | :--- | :--- | :--- |
| `PROJECT_ID` | **Yes** | Google Cloud Project ID hosting Cloud Run | `<YOUR_PROJECT_ID>` | `.env` / GCP |
| `REGION` | **Yes** | Cloud Run deployment region | `us-central1` | `.env` |
| `SERVICE_NAME` | **Yes** | Cloud Run service name | `mcp-secops-mcp-server` | `.env` |
| `CHRONICLE_PROJECT_ID` | Optional | GCP Project where Chronicle is provisioned (defaults to `PROJECT_ID`) | `<YOUR_CHRONICLE_PROJECT_ID>` | `.env` / GCP |
| `CHRONICLE_CUSTOMER_ID` | Optional | Chronicle Customer/Instance ID (UUID). Leave empty for fallback simulation mode. | `<YOUR_CHRONICLE_CUSTOMER_ID>` | Chronicle Console |
| `CHRONICLE_REGION` | Optional | Chronicle API Region (`us`, `eu`, `asia-southeast1`, `me-central2`) | `us` | `.env` |
| `RUNNER_SA` | Optional | Service account email of the calling agent (for IAM Invoker binding) | `runner-sa@<PROJECT_ID>.iam.gserviceaccount.com` | `.env` / IAM |
| `SECOPS_SA_PATH` | Optional | Path to local Service Account JSON key (if not using ADC) | `/path/to/sa.json` | Local File |
| `LOG_LEVEL` | Optional | Logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`) | `INFO` | `.env` |

---

## 🛠️ Step-by-Step Deployment

### Step 1: Copy and Configure `.env` File

1. **Copy the example configuration template**:
   ```bash
   cp .env.example .env
   ```

2. **Open and edit `.env`** using your preferred text editor (e.g., `nano`, `vim`, or VS Code):
   ```bash
   nano .env
   ```

3. **Populate your specific environment values**:
   ```env
   # Google Cloud Hosting Project ID (where Cloud Run is deployed)
   PROJECT_ID=<YOUR_GCP_PROJECT_ID>

   # Cloud Run Region (e.g., us-central1)
   REGION=us-central1

   # Service Name (e.g., mcp-secops-mcp-server)
   SERVICE_NAME=mcp-secops-mcp-server

   # Service Account of the calling agent (for IAM Invoker binding)
   RUNNER_SA=<YOUR_AGENT_RUNNER_SERVICE_ACCOUNT_EMAIL>

   # Chronicle / SecOps Instance Settings
   CHRONICLE_PROJECT_ID=<YOUR_CHRONICLE_PROJECT_ID>
   CHRONICLE_CUSTOMER_ID=<YOUR_CHRONICLE_CUSTOMER_ID>
   CHRONICLE_REGION=us

   # Logging
   LOG_LEVEL=INFO
   ```

### Step 2: Authenticate and Set Google Cloud Project

```bash
# Log in with your Google Cloud account
gcloud auth login

# Set active deployment project
gcloud config set project "$PROJECT_ID"
```

### Step 3: Enable Required Google Cloud APIs

```bash
gcloud services enable \
  run.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  chronicle.googleapis.com \
  iam.googleapis.com \
  --project="$PROJECT_ID"
```

### Step 4: Deploy to Google Cloud Run

#### Option A: Automated Script (Recommended)
Run the bundled deployment script:

```bash
chmod +x deploy.sh
./deploy.sh
```

The script will automatically:
1. Source `.env` configuration.
2. Enable necessary Google Cloud APIs.
3. Build and deploy container to Cloud Run with optimal settings (`--session-affinity`, `--min-instances=1`, `--timeout=300`).
4. Bind `roles/run.invoker` for your agent's service account and active gcloud user.
5. Print live service endpoints.

#### Option B: Direct `gcloud` Command
Alternatively, deploy directly using `gcloud run deploy`:

```bash
set -a && source .env && set +a

gcloud run deploy "$SERVICE_NAME" \
  --source=. \
  --region="$REGION" \
  --project="$PROJECT_ID" \
  --platform=managed \
  --ingress=all \
  --no-allow-unauthenticated \
  --session-affinity \
  --min-instances=1 \
  --max-instances=10 \
  --timeout=300 \
  --set-env-vars="CHRONICLE_CUSTOMER_ID=${CHRONICLE_CUSTOMER_ID},CHRONICLE_PROJECT_ID=${CHRONICLE_PROJECT_ID:-$PROJECT_ID},CHRONICLE_REGION=${CHRONICLE_REGION:-us},LOG_LEVEL=${LOG_LEVEL:-INFO}"
```

---

## 🔐 Step 5: Configure IAM Permissions

Grant `roles/run.invoker` to the Agent Runner Service Account:

```bash
if [ -n "$RUNNER_SA" ]; then
  gcloud run services add-iam-policy-binding "$SERVICE_NAME" \
    --region="$REGION" \
    --project="$PROJECT_ID" \
    --member="serviceAccount:${RUNNER_SA}" \
    --role="roles/run.invoker"
fi
```

Grant `roles/run.invoker` to your personal account for local testing:

```bash
ACTIVE_USER=$(gcloud config get-value account 2>/dev/null)
if [ -n "$ACTIVE_USER" ]; then
  gcloud run services add-iam-policy-binding "$SERVICE_NAME" \
    --region="$REGION" \
    --project="$PROJECT_ID" \
    --member="user:${ACTIVE_USER}" \
    --role="roles/run.invoker"
fi
```

---

## 🧪 Step 6: Testing & Verification

Retrieve your deployed Cloud Run service URL and an identity token:

```bash
SERVICE_URL=$(gcloud run services describe "$SERVICE_NAME" --region="$REGION" --project="$PROJECT_ID" --format="value(status.url)")
TOKEN=$(gcloud auth print-identity-token)

echo "Deployed Service URL: $SERVICE_URL"
```

### 1. Automated Test Suite
Run the included comprehensive test client:

```bash
TARGET_URL="$SERVICE_URL" AUTH_TOKEN="$TOKEN" python3 test_client.py
```

### 2. Manual HTTP Probes via cURL

#### Health Check
```bash
curl -i -H "Authorization: Bearer $TOKEN" "$SERVICE_URL/healthz"
```
*Expected Output*: `HTTP/2 200 OK` with `{"status":"ok","service":"secops-mcp-server",...}`

#### MCP Discovery Probe (Zero-Redirect GET)
```bash
curl -i -H "Authorization: Bearer $TOKEN" "$SERVICE_URL/mcp"
```
*Expected Output*: `HTTP/2 200 OK`

#### MCP Protocol Initialization (`initialize`)
```bash
curl -i -X POST "$SERVICE_URL/mcp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2024-11-05",
      "capabilities": {},
      "clientInfo": {"name": "test-client", "version": "1.0"}
    }
  }'
```

#### SecOps Tool Execution (`get_security_alerts`)
```bash
curl -i -X POST "$SERVICE_URL/mcp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "get_security_alerts",
      "arguments": {
        "severity": "CRITICAL",
        "limit": 5
      }
    }
  }'
```

#### List Detection Rules (`list_detection_rules`)
```bash
curl -i -X POST "$SERVICE_URL/mcp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
      "name": "list_detection_rules",
      "arguments": {
        "page_size": 10
      }
    }
  }'
```

---

## 🤖 Step 7: Security Agent & Gemini Enterprise Integration

To connect the SecOps MCP server to your security agents or Gemini Enterprise:

- **Protocol**: Model Context Protocol (MCP)
- **Transport**: `Streamable HTTP` (recommended) or `SSE`
- **Endpoint URL**: `https://<YOUR-CLOUD-RUN-URL>/mcp`
- **Authentication**: Service Account / Google Cloud OAuth2 Bearer Token
- **Tools Discovered**: 29 SecOps tools automatically enumerated via `tools/list`

---

## ❓ Troubleshooting & FAQs

### Issue: `401 Unauthorized` or `403 Forbidden`
- Ensure you generate a valid identity token: `gcloud auth print-identity-token`
- Verify the calling user or service account has been granted `roles/run.invoker` on the Cloud Run service.

### Issue: `307 Temporary Redirect` on `/mcp`
- The server has native support for `/mcp`, `/mcp/`, and `/mcp/{path}` to prevent trailing-slash redirects that break standard HTTP POST client implementations.

### Issue: Chronicle API Authentication
- If Chronicle is in a separate GCP project, ensure the Cloud Run service account has `roles/chronicle.viewer` or `roles/chronicle.admin` in the Chronicle project.
- If `CHRONICLE_CUSTOMER_ID` is unset, the MCP server automatically operates in simulated fallback mode for safe staging and development.

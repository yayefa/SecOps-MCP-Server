# Google SecOps MCP Server - Step-by-Step Cloud Run Deployment Guide

This guide details the complete, step-by-step process to deploy the **Google Chronicle Security Operations (SecOps) MCP Server** to Google Cloud Run using environment variables and Streamable HTTP transport.

---

## 📋 Table of Contents
1. [Architecture & Overview](#1-architecture--overview)
2. [Prerequisites](#2-prerequisites)
3. [Step 1: Configure Environment Variables](#step-1-configure-environment-variables)
4. [Step 2: Authenticate and Set Google Cloud Project](#step-2-authenticate-and-set-google-cloud-project)
5. [Step 3: Enable Required Google Cloud APIs](#step-3-enable-required-google-cloud-apis)
6. [Step 4: Deploy to Cloud Run](#step-4-deploy-to-cloud-run)
7. [Step 5: Configure IAM Permissions](#step-5-configure-iam-permissions)
8. [Step 6: Test and Verify Endpoints](#step-6-test-and-verify-endpoints)
9. [Step 7: Connect to Security Agents & Gemini Enterprise](#step-7-connect-to-security-agents--gemini-enterprise)
10. [Troubleshooting & FAQs](#10-troubleshooting--faqs)

---

## 1. Architecture & Overview

* **Protocol**: Model Context Protocol (MCP) Standard (`2024-11-05`)
* **Transport**: Streamable HTTP / SSE
* **Official Tools**: All 29 Google SecOps tools (Investigation, YARA-L Rules, Ingestion, Parsers, Data Tables, Reference Lists)
* **Hosting**: Google Cloud Run (Serverless Container with HTTPS)

---

## 2. Prerequisites

Ensure you have the following installed and configured:
* [Google Cloud SDK (`gcloud`)](https://cloud.google.com/sdk/docs/install)
* `curl` and `python3` (3.10+)
* An active Google Cloud Project with Cloud Run and Cloud Build enabled

---

## Step 1: Configure Environment Variables

Create or update your `.env` file in the project directory:

```bash
cp .env.example .env
```

Populate the `.env` file with your specific environment values:

```env
# ==============================================================================
# GOOGLE CLOUD PLATFORM CONFIGURATION
# ==============================================================================
PROJECT_ID=<YOUR_GCP_PROJECT_ID>
REGION=<YOUR_GCP_REGION>
SERVICE_NAME=<YOUR_SERVICE_NAME>

# ==============================================================================
# GOOGLE SECOPS (CHRONICLE) CONFIGURATION
# ==============================================================================
CHRONICLE_CUSTOMER_ID=<YOUR_CHRONICLE_CUSTOMER_ID>
CHRONICLE_PROJECT_ID=<YOUR_CHRONICLE_PROJECT_ID>
CHRONICLE_REGION=<YOUR_CHRONICLE_REGION>

# ==============================================================================
# IAM & AGENT RUNNER SERVICE ACCOUNT
# ==============================================================================
AGENT_RUNNER_SA=<YOUR_AGENT_RUNNER_SERVICE_ACCOUNT_EMAIL>

# ==============================================================================
# SERVER RUNTIME OPTIONS
# ==============================================================================
PORT=8080
LOG_LEVEL=INFO
```

### Export Variables to Shell

Load the variables into your active terminal session:

```bash
set -a
source .env
set +a
```

---

## Step 2: Authenticate and Set Google Cloud Project

Authenticate your gcloud CLI session and set the target project:

```bash
# Authenticate User Account
gcloud auth login

# Set active project
gcloud config set project "$PROJECT_ID"
```

---

## Step 3: Enable Required Google Cloud APIs

Enable Cloud Run, Cloud Build, Artifact Registry, and Chronicle APIs:

```bash
gcloud services enable \
  run.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  chronicle.googleapis.com \
  iam.googleapis.com \
  --project="$PROJECT_ID"
```

---

## Step 4: Deploy to Cloud Run

Deploy directly from source using `gcloud run deploy`:

```bash
gcloud run deploy "$SERVICE_NAME" \
  --source=. \
  --region="$REGION" \
  --project="$PROJECT_ID" \
  --platform=managed \
  --no-allow-unauthenticated \
  --set-env-vars="CHRONICLE_CUSTOMER_ID=${CHRONICLE_CUSTOMER_ID},CHRONICLE_PROJECT_ID=${CHRONICLE_PROJECT_ID},CHRONICLE_REGION=${CHRONICLE_REGION},LOG_LEVEL=${LOG_LEVEL}" \
  --memory=1Gi \
  --cpu=1 \
  --min-instances=0 \
  --max-instances=10 \
  --timeout=300
```

> **Tip**: You can also run the automated deployment script:
> ```bash
> chmod +x deploy.sh
> ./deploy.sh
> ```

---

## Step 5: Configure IAM Permissions

Grant the `roles/run.invoker` role to your Agent Runner Service Account and administrator user so they can securely invoke the Cloud Run service:

```bash
# 1. Grant Invoker role to Agent Runner Service Account
if [ -n "$AGENT_RUNNER_SA" ]; then
  gcloud run services add-iam-policy-binding "$SERVICE_NAME" \
    --region="$REGION" \
    --project="$PROJECT_ID" \
    --member="serviceAccount:${AGENT_RUNNER_SA}" \
    --role="roles/run.invoker"
fi

# 2. Grant Invoker role to active user for testing
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

## Step 6: Test and Verify Endpoints

Obtain the deployed Cloud Run service URL:

```bash
SERVICE_URL=$(gcloud run services describe "$SERVICE_NAME" --region="$REGION" --project="$PROJECT_ID" --format="value(status.url)")
TOKEN=$(gcloud auth print-identity-token)

echo "Service URL: $SERVICE_URL"
```

### 1. Health Probe Verification
```bash
curl -i -s -H "Authorization: Bearer $TOKEN" "$SERVICE_URL/health"
```
*Expected Output*: `HTTP/2 200 OK` with `{"status":"ok","service":"secops-mcp-server",...}`

### 2. Streamable HTTP Discovery Probe (`/mcp` and `/mcp/`)
```bash
curl -i -s -H "Authorization: Bearer $TOKEN" "$SERVICE_URL/mcp"
```
*Expected Output*: `HTTP/2 200 OK` (No 307 redirect!)

### 3. MCP Protocol Initialization
```bash
curl -i -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "$SERVICE_URL/mcp" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test-client","version":"1.0"}}}'
```
*Expected Output*: `HTTP/2 200 OK` with `protocolVersion: "2024-11-05"`.

### 4. Execute a SecOps MCP Tool Call (`get_security_alerts`)
```bash
curl -i -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "$SERVICE_URL/mcp" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_security_alerts","arguments":{"severity":"CRITICAL","limit":1}}}'
```
*Expected Output*: `HTTP/2 200 OK` with JSON-RPC alert investigation details.

### 5. Automated Python Test Suite
Run the included comprehensive test client:
```bash
TARGET_URL="$SERVICE_URL" AUTH_TOKEN="$TOKEN" python3 test_client.py
```

---

## Step 7: Connect to Security Agents & Gemini Enterprise

To connect the SecOps MCP server to your security agents or Gemini Enterprise:

1. **MCP Endpoint URL**:
   ```text
   https://<your-service-url>/mcp
   ```
2. **Transport**: `Streamable HTTP` (or `SSE`)
3. **Authentication**: `Google Cloud IAM / OAuth Bearer Token`
4. **Tool Capability**: 29 Official Tools automatically discovered via `tools/list`.

---



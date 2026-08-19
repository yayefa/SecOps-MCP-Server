# Google SecOps (Chronicle) MCP Server (Streamable HTTP)

Enterprise Model Context Protocol (MCP) server providing Google SecOps (Chronicle) SIEM/SOAR telemetry, alert triage, Universal Data Model (UDM) search, and YARA-L detection rule management using **Streamable HTTP** (`streamable-http`) transport—the current MCP specification standard.

---

## 🌟 Overview: Streamable HTTP Transport

Streamable HTTP is the standard remote transport for Model Context Protocol (MCP) servers:
- **Unified Endpoint (`/mcp`)**: Single endpoint for client-to-server messaging, tool discovery, and bi-directional communication.
- **Production Scalability**: Seamlessly deployed to stateless and containerized platforms like **Google Cloud Run**.
- **Container Health Probes**: Built-in `/health` liveness and readiness probes.
- **Enterprise Security**: Native Google Cloud IAM authentication (`roles/run.invoker`) with OAuth2/OIDC token support.

---

## 🛠️ Implemented SecOps Tools (All 29 Official Tools)

### 1. Security Investigation & Alert Tools
- `search_security_events`: Searches SecOps events via natural language or UDM queries.
- `get_security_alerts`: Retrieves alerts filtered by severity (`CRITICAL`, `HIGH`, etc.) and status.
- `get_security_alert_by_id`: Fetches detailed alert metadata and MITRE ATT&CK mapping.
- `do_update_security_alert`: Updates triage status and appends analyst notes.
- `lookup_entity`: 360-degree risk telemetry profile for IP, Domain, Hostname, User, or Hash.
- `get_ioc_matches`: Retrieves Indicators of Compromise matches over a lookback window.
- `get_threat_intel`: Query SecOps SecLM threat intelligence insights.

### 2. Detection Rules Management
- `list_security_rules`: Lists custom and curated YARA-L detection rules.
- `search_security_rules`: Searches detection rules using regex patterns or keywords.
- `get_rule_detections`: Retrieves detections triggered by a specific rule.
- `list_rule_errors`: Lists execution or compilation errors for rules.
- `create_rule`: Creates new YARA-L 2.0 detection rules.
- `test_rule`: Backtests detection rules against historical telemetry.
- `validate_rule`: Validates syntax and structure of YARA-L definitions.

### 3. Log Ingestion Tools
- `ingest_raw_log`: Ingests raw log payloads (JSON, XML, CEF, syslog).
- `ingest_udm_events`: Ingests structured Universal Data Model events.
- `get_available_log_types`: Enumerate supported log types (Cloud Audit, EDR, Okta, Zscaler, etc.).

### 4. Parser Management Tools
- `create_parser`: Creates custom log parsers (CBN syntax).
- `get_parser`: Retrieves parser configuration and filtering code.
- `activate_parser`: Activates parser for live ingestion processing.
- `deactivate_parser`: Deactivates an active parser.
- `run_parser_against_sample_logs`: Tests parser rules against sample log strings.

### 5. Data Tables & Reference Lists
- `create_data_table` / `add_rows_to_data_table` / `list_data_table_rows` / `delete_data_table_rows`
- `create_reference_list` / `get_reference_list` / `update_reference_list`

---

## 🚀 Quick Start: Run Locally

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Start the Server
```bash
export PORT=8080
export HOST=0.0.0.0
python server.py
```

The Streamable HTTP server is now accessible at:
- Streamable HTTP Endpoint: `http://localhost:8080/mcp`
- Health Probe: `http://localhost:8080/healthz`

---

## ☁️ One-Click Deployment to Google Cloud Run

Deploy directly using the automated deployment script:

```bash
chmod +x deploy.sh
./deploy.sh
```

### Deployment Steps Executed:
1. **[Step 1/5] Custom Variables**: Loads `.env` file and merges custom variables.
2. **[Step 2/5] Enable APIs**: Enables Cloud Run, Cloud Build, and Chronicle APIs.
3. **[Step 3/5] Cloud Run Deploy**: Deploys container with Streamable HTTP transport.
4. **[Step 4/5] IAM Policy Bindings**: Grants `roles/run.invoker` to agent runner SA and active user.
5. **[Step 5/5] Verification**: Checks `/healthz` probe and prints endpoint URLs.

---

## 🧪 Testing and Inspection

### Option A: Run Test Suite
```bash
python3 test_client.py
```

### Option B: Using the MCP Inspector UI
Launch the official Model Context Protocol Inspector:
```bash
npx -y @modelcontextprotocol/inspector
```
Connect via HTTP transport to `http://localhost:8080/mcp`.

### Option C: Connect via Google ADK / GenAI Agent
Set the environment variable in your agent configuration:
```bash
export SECOPS_MCP_URL="https://<your-cloud-run-service-url>/mcp"
```

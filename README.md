# Sovereign AI Gateway

**A local-first, security-focused proof of concept for controlled AI access to Oracle data.**

Sovereign AI Gateway demonstrates how a locally hosted language model can interpret a user's request and retrieve narrowly scoped information from an Oracle database through an authenticated API boundary—without giving the model database credentials or unrestricted SQL access.

> **Project status:** Experimental proof of concept. The current demonstration uses Gemma 4 through local Ollama and a synthetic department schema in Oracle's hosted APEX/ORDS service. It is not a production security product, comprehensive DLP system, certified SIEM or fully on-premises/air-gapped deployment.

## What it demonstrates

- **Local inference:** Gemma 4 (`gemma4:e4b`) runs locally through Ollama; prompts are not sent to a cloud LLM provider by this integration.
- **Prompt policy:** Pattern-based detection supports `redact` and `block` modes on the agent endpoint.
- **Controlled tool calling:** Gemma can select only from a fixed server-side allowlist of Oracle operations.
- **Oracle integration:** FastAPI calls Oracle APEX/ORDS over HTTPS using OAuth 2.0 client credentials.
- **Read-only data access:** The demo exposes a fixed department list and a PL/SQL-backed department summary; no arbitrary SQL execution is provided.
- **Auditability:** Gateway events use HMAC prompt fingerprints and a SHA-256 hash chain. The summary operation also writes an Oracle-side audit record linked by request ID.
- **Monitoring:** A read-only dashboard shows gateway events, policy outcomes, tool activity, Oracle audit rows and correlation results.

## Architecture

![Sovereign AI Gateway architecture](docs/images/architecture.svg)

See [Architecture and data flow](docs/ARCHITECTURE.md) for the editable Mermaid diagrams, components, route inventory and sequence flow. See [Technical Security Notes](docs/SECURITY.md) for the threat model, security controls, limitations and hardening backlog.

## Demonstrated request

Example user question:

> How many employees work in IT and what is its monthly budget?

Gemma 4 selects the approved `department_summary` tool with `department_code=IT`. The gateway validates the tool request, obtains/caches an ORDS bearer token, calls the fixed ORDS endpoint, receives the result from the Oracle PL/SQL package and asks Gemma to phrase the result.

Example response data from the synthetic demo schema:

```json
{
  "department_code": "IT",
  "department_name": "Information Technology",
  "headcount": 18,
  "monthly_budget": 42000,
  "currency_code": "USD",
  "data_source": "oracle_apex_ords"
}
```

The agent response includes the natural-language answer, the selected tool and arguments, the structured data, policy action, source label and a request ID.

## Security behavior

| Mode | Detected sensitive pattern | Agent behavior |
|---|---|---|
| `redact` | Matching values replaced with category placeholders before local model inference | Request may continue using sanitized text |
| `block` | Finding recorded in the gateway audit log | HTTP 403 before the model or Oracle tool is called |
| No finding | No configured pattern detected | Request proceeds to local Gemma |

The detector set is deliberately limited and pattern-based. It is not comprehensive DLP and must not be used as the only control protecting real sensitive data. See [Technical Security Notes](docs/SECURITY.md).

## Technology

- Python 3.13
- FastAPI and Uvicorn
- Pydantic
- HTTPX
- Ollama and Gemma 4
- Oracle APEX 26.2 / ORDS
- PL/SQL
- SQLite audit store
- SHA-256 audit hash chain and HMAC-SHA-256 prompt fingerprints

## Prerequisites

- Python 3.11+ (the development environment was tested with Python 3.13).
- Ollama installed and running locally.
- The `gemma4:e4b` model (or a compatible tool-calling model configured for the project).
- An Oracle APEX workspace with a REST-enabled schema and ORDS access. The example uses the `sagdemo` schema alias on `oracleapex.com`.
- An ORDS OAuth client using the Client Credentials grant, assigned the `AI_GATEWAY_READER` role and `ai.gateway.access` privilege.
- The project's Oracle demo objects, PL/SQL package, REST module and audit extension installed.

All records in the provided Oracle demo schema are synthetic. Do not connect this demonstration to production payroll, HR or finance data.

## Quick start

### 1. Clone and create a virtual environment

```powershell
git clone https://github.com/<your-account>/sovereign-ai-gateway.git
cd sovereign-ai-gateway
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

If the repository is not installed in editable mode, set the source path before starting the application:

```powershell
$env:PYTHONPATH = "src"
```

### 2. Configure environment variables

Copy `.env.example` to `.env` and supply your own secrets and ORDS OAuth client values.

```dotenv
# Gateway secrets — generate unique random values; never commit them.
CLIENT_API_KEY=replace-with-a-long-random-client-key
ADMIN_API_KEY=replace-with-a-long-random-admin-key
AUDIT_HMAC_KEY=replace-with-a-long-random-hmac-secret

# Local audit store and runtime policy
DATABASE_PATH=./data/audit.sqlite3
POLICY_MODE=redact
AUDIT_CAPTURE=metadata
GATEWAY_PROVIDER=ollama
GATEWAY_MODEL=gemma4:e4b

# Local Ollama service
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL=gemma4:e4b
OLLAMA_AGENT_TIMEOUT_SECONDS=300
OLLAMA_KEEP_ALIVE=15m

# Oracle APEX / ORDS — use your own OAuth client credentials
ORDS_ENABLED=true
ORDS_BASE_URL=https://oracleapex.com/ords/sagdemo
ORDS_CLIENT_ID=replace-with-your-ords-client-id
ORDS_CLIENT_SECRET=replace-with-your-ords-client-secret
ORDS_TIMEOUT_SECONDS=30
```

Do not add a direct Oracle username, password or DSN for the hosted APEX/ORDS integration. The gateway calls ORDS over HTTPS and does not use SQL*Net or `python-oracledb` for this path.

### 3. Start Ollama and the gateway

Verify the model is installed:

```powershell
ollama list
```

Start Ollama if it is not already running, then start FastAPI from the repository root:

```powershell
python -m uvicorn sovereign_gateway.main:app --app-dir src --reload
```

Open the interactive API documentation at `http://127.0.0.1:8000/docs`.

### 4. Try the agent

Send `POST /v1/agent/chat` with `X-API-Key` set to your gateway `CLIENT_API_KEY`:

```json
{
  "message": "How many employees work in IT and what is its monthly budget?"
}
```

Expected behavior: Gemma selects `department_summary`, the gateway validates `department_code=IT`, ORDS calls the approved PL/SQL operation, and the model returns an answer grounded in the Oracle result.

### 5. Open the monitoring dashboard

Open `http://127.0.0.1:8000/admin/dashboard` and connect with the gateway `ADMIN_API_KEY`. The dashboard is read-only and displays bounded gateway/Oracle audit data and local audit-chain verification status.

## Gateway API overview

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/agent/chat` | Natural-language agent with allowlisted Oracle tools |
| `GET` | `/v1/oracle/health` | ORDS connectivity/authentication check |
| `GET` | `/v1/oracle/departments` | List synthetic departments |
| `POST` | `/v1/oracle/department-summary` | Read one approved department summary |
| `GET` | `/v1/oracle/tools` | Static approved tool metadata |
| `GET` | `/admin/audit` | Read gateway audit events |
| `GET` | `/admin/audit/verify` | Verify local SHA-256 audit chain |
| `GET` | `/admin/dashboard` | Monitoring dashboard |

See [Architecture](docs/ARCHITECTURE.md) for the admin dashboard data APIs and the corresponding ORDS resources.

## Screenshots

Screenshots are intentionally kept separate until reviewed and sanitized. See [Screenshot Checklist](docs/SCREENSHOTS.md) for the suggested filenames and capture targets. Place approved files in `docs/images/` before embedding them here.

Suggested captures:

- Dashboard overview and audit-chain status.
- Successful Gemma-to-Oracle tool execution.
- Redact mode with synthetic email data.
- Block mode returning HTTP 403.
- Unsupported operation rejected.
- Oracle-side audit row showing the shared gateway request ID.

## Documentation

- [Architecture and data flow](docs/ARCHITECTURE.md)
- [Technical Security Notes and Threat Model](docs/SECURITY.md)
- [Screenshot Checklist](docs/SCREENSHOTS.md)
- [Architecture diagram source](docs/diagrams/architecture.mmd)
- [Agent sequence diagram source](docs/diagrams/sequence.mmd)

## Validation status

The developer has manually verified the following in the demonstration environment:

- Local Gemma 4 chat through Ollama.
- Native selection of `department_summary` and `list_departments`.
- Protected ORDS OAuth token issuance and department REST calls from Python.
- Successful natural-language department summary from Oracle synthetic data.
- Redact mode allows a sanitized synthetic prompt to continue.
- Block mode returns HTTP 403 for a synthetic email prompt.
- Unsupported employee salary/password requests do not map to an approved tool.
- Monitoring dashboard displays gateway events, Oracle audit records and hash-chain verification.

Component test suites using mocked HTTPX/ORDS/Ollama services are included in the development patches. Run the repository's full test suite before publishing a release; do not infer production readiness from the manual demonstration.

## Known limitations

- Pattern-based sensitive-data detection has false positives and false negatives.
- The agent currently permits at most one Oracle tool call per user request.
- The two tools cover only synthetic department data.
- The current list-departments ORDS collection query does not create its own Oracle audit row; it is logged by the gateway. Department-summary calls do create an Oracle audit row.
- Gateway actor identity is currently a shared service label, not a verified end-user identity.
- SQLite hash chaining is tamper-evident but not immutable against a privileged attacker who can rewrite the database and recompute hashes.
- The dashboard shows a bounded event window rather than lifetime totals.
- Oracle APEX/ORDS in this demo is hosted by Oracle. The architecture is not fully on-premises or air-gapped.
- No production SSO, per-user authorization, rate limiting, comprehensive prompt-injection defense, high availability, externally anchored immutable audit storage or formal security certification is provided.

See [Technical Security Notes](docs/SECURITY.md) for the full threat model and production-hardening backlog.

## Contributing and responsible use

This is a learning and collaboration project. Contributions should preserve the fixed tool allowlist, avoid arbitrary SQL interfaces, keep secrets out of source control, and add tests for security-relevant behavior. Use synthetic data in issues, screenshots and pull requests.

## License

Add the project's chosen license file before publishing. Do not assume a license from this documentation pack.

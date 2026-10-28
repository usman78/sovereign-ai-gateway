# Technical Security Notes and Threat Model

## 1. Purpose and security posture

Sovereign AI Gateway is an educational proof of concept that demonstrates local LLM inference, prompt-pattern inspection, a fixed tool allowlist, OAuth-protected Oracle REST access and correlated application/database audit records.

It is **not** a production security gateway, a comprehensive DLP product, a certified SIEM, an immutable audit service or a compliance certification. Its current Oracle database contains synthetic department data and is hosted on Oracle's APEX evaluation service. The design demonstrates selected controls; it does not establish complete data sovereignty or an air-gapped deployment.

## 2. Assets to protect

| Asset | Examples | Security concern |
|---|---|---|
| User prompts | Business questions, identifiers, credentials accidentally pasted into text | Sensitive content may be exposed to a model or retained in logs |
| ORDS client secret | OAuth client credential in `.env` | Unauthorized access to the protected ORDS module if stolen |
| ORDS bearer token | In-memory token returned by `/oauth/token` | Temporary authenticated access; must not be logged or disclosed |
| Gateway API key | `CLIENT_API_KEY` | Access to client-facing gateway operations |
| Administrator key | `ADMIN_API_KEY` | Access to gateway audit and monitoring APIs |
| Audit HMAC key | `AUDIT_HMAC_KEY` | Protects prompt fingerprints against straightforward offline guessing |
| Oracle demo data | Department headcounts and budgets | Unauthorized disclosure or modification |
| Audit records | SQLite gateway events and `AI_GATEWAY_AUDIT` rows | Detection, reconstruction and correlation of operations |
| Runtime configuration | Model, provider, prompt policy and capture mode | Unauthorized changes could weaken controls or redirect processing |

## 3. Trust boundaries

1. **Client to FastAPI:** Requests are untrusted. The gateway requires `CLIENT_API_KEY` on client-facing API routes.
2. **Gateway to local Ollama:** The local model is a separate process. Its output, including tool-call names and arguments, is untrusted until validated by the gateway.
3. **Gateway to ORDS:** The gateway uses a server-held OAuth client credential and HTTPS. Only fixed resource paths are called.
4. **ORDS to PL/SQL/data:** ORDS checks its configured role/privilege; the PL/SQL package runs the fixed read-only summary operation against synthetic demo rows.
5. **Application to local SQLite:** Audit events are written to the local audit store. The SHA-256 chain detects modifications but is not immutable against a privileged attacker who can rewrite the whole file and recompute hashes.
6. **Administrator browser to dashboard APIs:** Dashboard JSON endpoints require `ADMIN_API_KEY` through `X-Admin-Key`. The page keeps the key in JavaScript memory and does not place it in localStorage or URLs.
7. **Local demo to hosted Oracle service:** The Ollama model runs locally, but APEX/ORDS is hosted by Oracle. Approved tool arguments and Oracle result data traverse HTTPS to/from that hosted service. This demonstration is not fully on-premises or air-gapped.

## 4. Prompt inspection and policy enforcement

The gateway applies pattern-based inspection to the message sent to `/v1/agent/chat`. The current detector set includes patterns for:

- Email addresses.
- Phone-like numeric strings.
- Pakistani CNIC-shaped values (`#####-#######-#`).
- Simple password assignments such as `password=value`, `passwd=value` or `pwd=value`.
- Several common API-key patterns, including `sk-...`, `ghp_...` and `AKIA...` forms.

### Redact mode

When findings are detected and the active policy is `redact`, the detected substrings are replaced with category placeholders before the prompt is sent to Gemma 4. The operation may continue if the sanitized request maps to an approved tool. The original raw prompt is not stored by the default metadata audit mode; a keyed HMAC fingerprint and category counts are recorded.

### Block mode

When findings are detected and the active policy is `block`, the gateway records `agent.request.blocked` and returns HTTP 403 before the model or Oracle tool is called. This has been manually validated with a synthetic email prompt.

### Limitations

These are regex/pattern detectors, not comprehensive DLP. They can miss sensitive data, misclassify ordinary text, or fail to recognize non-text payloads, encoded values, structured files, tool results or secrets in other formats. They do not identify all personal information, financial information, source code secrets or confidential business data. Do not rely on them as the sole protection for real sensitive information.

The prompt policy described here is applied by the agent route. The direct `/v1/oracle/*` API endpoints are separately protected by the gateway client key and expose only fixed synthetic-data operations; they do not provide the same free-text prompt inspection step. Treat API-key holders as trusted service callers and do not expose these development endpoints publicly.

## 5. LLM and tool-call boundary

Gemma 4 runs locally through Ollama. It receives a static tool definition list containing only:

- `list_departments` — no arguments.
- `department_summary` — requires `department_code` in `IT`, `HR`, `FIN`, `OPS`.

The gateway enforces the tool boundary independently of the model:

- Tool names must match the server-side allowlist.
- Arguments must parse as a JSON object.
- Pydantic validation rejects extra or malformed arguments.
- Department codes are normalized and checked against the supported set.
- Exactly one tool call is allowed per user turn in the current implementation.
- No model-supplied URL, SQL, schema name, table name, package name, procedure name or HTTP method is accepted.
- The second LLM call receives the tool result but is made without tool definitions. Further tool calls are rejected rather than chained automatically.

The model's system prompt is guidance, not an authorization mechanism. Security depends on server-side validation and the fixed ORDS operations.

## 6. Oracle and ORDS access controls

The gateway uses the ORDS OAuth 2.0 client-credentials flow:

1. It posts to the schema token endpoint with HTTP Basic client authentication and `grant_type=client_credentials` as form data.
2. It validates the token response and caches the bearer token in process memory.
3. The cache uses an early-refresh margin before expiry; an upstream 401 triggers one token refresh/retry.
4. API calls use `Authorization: Bearer <token>` and fixed server-side paths.

The ORDS module is protected by the `AI_GATEWAY_READER` role and `ai.gateway.access` privilege. The Python gateway has no direct Oracle SQL*Net connection and no database driver is required for the ORDS path.

### Database operations

- The department list is a fixed read-only collection query against `AI_DEPARTMENTS`.
- The department summary invokes `AI_GATEWAY_API.GET_DEPARTMENT_SUMMARY`, which performs a fixed SELECT for the normalized department code and writes a separate audit record.
- No endpoint accepts arbitrary SQL or data-modification statements.
- The demo data is synthetic. Do not REST-enable production employee, payroll or finance tables for this PoC.

The summary operation is registered as an ORDS PL/SQL handler using POST. POST is the HTTP handler method; the operation itself is read-only.

## 7. Authentication and authorization

| Credential | Used by | Header/protocol | Scope |
|---|---|---|---|
| `CLIENT_API_KEY` | Client calling FastAPI | `X-API-Key` | Client-facing gateway endpoints |
| `ADMIN_API_KEY` | Dashboard administrator | `X-Admin-Key` | Dashboard metrics, event and correlation APIs; existing admin audit APIs |
| ORDS client ID/secret | Python ORDS client | OAuth Basic Auth at token endpoint | Service-level ORDS privilege |
| ORDS bearer token | Python ORDS client | `Authorization: Bearer` | Calls protected `ai.gateway` resources |

The current gateway dependency identifies API-key-authenticated clients with a generic service actor (`api-client`). This is not per-human identity. Before multi-user or production use, integrate an identity provider and propagate a verified end-user identity/authorization context to database auditing.

Request IDs are correlation identifiers, not credentials, bearer tokens or proof of identity.

## 8. Audit and monitoring

### Gateway audit store

The local SQLite store records structured event metadata. Relevant agent event types include:

- `agent.requested`
- `agent.request.blocked`
- `agent.completed_without_tool`
- `agent.tool.requested`
- `agent.tool.rejected`
- `agent.tool.failed`
- `agent.tool.succeeded`
- `agent.completed`

The ORDS connector additionally records events such as `ords.health.requested`, `ords.health.succeeded`, `ords.departments.requested`, `ords.departments.succeeded`, `ords.department_summary.requested` and `ords.department_summary.succeeded` (failure variants are also recorded).

Prompt fingerprints use HMAC-SHA-256 with `AUDIT_HMAC_KEY`. The fingerprint is deterministic for the same canonical prompt/key pair and therefore remains linkable; it is not anonymization. Protect the HMAC key and avoid exposing fingerprints publicly.

SQLite events are linked through a SHA-256 hash chain. Verification detects accidental or partial tampering. A privileged attacker who can rewrite the complete SQLite database can recompute the hashes; external signing/anchoring is needed to make tampering materially harder to conceal.

### Oracle audit store

`AI_GATEWAY_AUDIT` stores Oracle-side summary operation details including the gateway request ID, operation name, department code, actor, outcome and safe details. The department-summary PL/SQL operation writes this row as an autonomous transaction.

The current `list_departments` collection-feed handler is a fixed read-only query and does not itself add an Oracle-side audit row. Its request is recorded in the Python gateway audit store.

### Dashboard

The dashboard is read-only. It reads recent gateway events, verifies the SQLite hash chain, fetches the Oracle audit feed through ORDS and compares request IDs. The current display is bounded to up to 1,000 recent gateway events and up to 100 Oracle audit rows; displayed metrics are not lifetime totals.

The HTML page shell does not embed audit data. Dashboard APIs require `X-Admin-Key`. The browser page retains the entered admin key in page memory only and clears it on disconnect/refresh; it does not put the key into the URL or localStorage.

### Capture mode

`AUDIT_CAPTURE=metadata` is the recommended default. If the optional redacted-content capture mode is enabled, sanitized message content may still contain confidential information that pattern detection did not catch. Apply a reviewed retention/access policy before enabling it with anything other than synthetic data.

## 9. Failure behavior

- If the pre-call gateway audit write fails, the agent request is stopped before model/tool processing.
- If the pre-call tool audit write fails, the Oracle operation is not started.
- If ORDS OAuth or the API call fails, the gateway returns a sanitized error code and records a failure event where possible.
- If the post-call audit write fails, the database read may already have occurred; the two audit stores are not a distributed transaction.
- An ORDS 401 may cause one token refresh and one retry.
- The dashboard reports audit-chain verification status; it does not repair or silently rewrite a damaged chain.

## 10. Deployment and data handling guidance

For the current demonstration:

- Use synthetic department data only.
- Bind Uvicorn to localhost (`127.0.0.1`) and do not expose the development server to the public internet.
- Keep `.env` out of Git and restrict filesystem permissions on it.
- Keep the SQLite audit database and backups out of Git.
- Never commit OAuth client secrets, bearer tokens, API keys, Postman environments containing credentials, or screenshots showing them.
- Keep TLS verification enabled; do not use `verify=False` or `--insecure` as a workaround.
- Keep Ollama bound to a trusted local interface and do not expose its unauthenticated local API to untrusted networks.
- Use metadata audit capture unless a documented reason exists to retain sanitized message content.
- Rotate any credential that has been pasted into chat, committed or otherwise disclosed.

## 11. Production-hardening backlog

Before using real company data or deploying beyond a local demonstration, address at least the following:

1. Replace shared static API keys with OIDC/SSO or another managed identity provider; authorize individual users and roles.
2. Enforce user- and row-level access in the application and database; define how the real end-user identity is propagated into Oracle sessions/audit.
3. Replace regex-only inspection with a tested DLP policy covering structured inputs, attachments, tool arguments and retrieved results.
4. Add rate limits, request quotas, abuse monitoring and concurrency controls.
5. Use a production ASGI server behind a TLS-terminating reverse proxy with hardened headers and explicit network rules.
6. Move audit records to a separately administered append-only/WORM-capable destination and periodically sign or externally anchor chain heads.
7. Define retention, deletion, backup, restore, access-review and incident-response procedures for prompts, fingerprints and audit events.
8. Rotate OAuth/API/HMAC secrets and use a proper secret manager rather than a plaintext developer `.env` file.
9. Add integration monitoring, alerts, health checks, dependency pinning and vulnerability scanning.
10. Perform prompt-injection, data-exfiltration, model-output, SSRF, authorization-bypass and tenant-isolation testing.
11. For a data-sovereignty deployment, move Oracle Database and ORDS to infrastructure controlled by the organization. The current public APEX workspace is hosted by Oracle and is not an air-gapped or fully on-premises environment.
12. Add Oracle-side auditing for all exposed read operations, including the department collection endpoint, if full database-side operation traceability is required.

## 12. Security test checklist

- [x] Local Gemma 4 inference through Ollama.
- [x] Successful native tool selection for an approved department operation.
- [x] Unknown employee salary/password operation rejected without a matching approved tool.
- [x] Redact mode sanitizes a synthetic email and allows the safe department operation.
- [x] Block mode returns HTTP 403 for a synthetic email before model/Oracle tool execution.
- [x] ORDS OAuth client-credentials exchange works from the Python gateway after setting the tested User-Agent.
- [x] Protected ORDS department endpoints return the expected synthetic data.
- [x] Department-summary operation records an Oracle-side audit row with a gateway request ID.
- [x] Dashboard reads gateway and Oracle audit data and displays hash-chain verification.
- [ ] Verify that a blocked request ID is absent from Oracle audit records after the final block-mode test.
- [ ] Verify matching request IDs in both audit stores for a successful agent request.
- [ ] Complete deployment-specific review before any non-local use.

The checked items describe the developer's reported manual validation in the demonstration environment. The unchecked items remain explicit follow-up verification tasks.

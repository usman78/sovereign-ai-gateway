# Threat model (proof-of-concept scope)

## Assets

- Enterprise text submitted to an AI interface, including personal data, credentials and commercially sensitive context.
- Provider/model selection and gateway policy configuration.
- The audit history used to investigate AI requests and administrative changes.
- The gateway's client, administrator and audit-fingerprint secrets.

## Trust boundaries

1. **User/application → gateway:** requests cross an authentication and input-inspection boundary.
2. **Gateway → model provider:** only sanitized messages should cross this boundary. The default mock provider is offline; the optional Ollama adapter is intended for a locally controlled endpoint.
3. **Administrator → gateway configuration:** a separate admin credential is required; changes are recorded with before/after snapshots.
4. **Gateway → audit store:** a request is not sent to a model if its pre-call audit event cannot be written.

## Threats addressed by this prototype

| Threat | Prototype control | Remaining limitation |
|---|---|---|
| Common PII or secret accidentally included in a prompt | Pattern inspection and redaction | Regex patterns are incomplete and can produce false positives/negatives. |
| Sensitive prompt reaches the model despite a policy decision | Optional block mode; provider adapter receives only the sanitized message list | Does not inspect files, images, embeddings, tool arguments or data fetched later by an agent. |
| Request is sent while audit storage is unavailable | Fail-closed behavior before provider invocation | A provider response can be generated before a later response-audit write fails. |
| Operator changes model or policy without a record | Admin endpoint writes a before/after configuration event | Direct database edits or code/config changes outside this API are not fully governed. |
| Existing audit event is edited | Sequential hash-chain verification; startup checks existing chain and latest configuration snapshot | A privileged attacker able to rewrite the entire database can recompute the chain. |
| Raw prompt content leaks through routine audit logs | Metadata-only capture by default; HMAC fingerprints | Fingerprints remain linkable; HMAC key compromise weakens this property. |

## Explicit non-goals

This project does not currently defend against prompt injection, jailbreaks, model hallucinations, malicious or compromised model weights, compromised gateway hosts, denial of service, malicious administrators, insecure browser clients, arbitrary SQL execution, or privilege escalation inside Oracle. It is not a substitute for network segmentation, endpoint security, database controls, a proper identity provider, or an organization's DLP program.

## Operational assumptions

- The gateway and its SQLite file run on a trusted host.
- TLS is terminated by a trusted reverse proxy before any non-loopback deployment.
- Client and admin secrets are unique, random and stored outside source control.
- Ollama is reachable only on a trusted network segment. A URL configured as “local” should be verified against actual host/network routing.
- Redacted-content capture is enabled only with synthetic data or an approved retention/access policy.

## Production hardening priorities

1. Use SSO/OIDC and per-user or per-service authorization instead of shared static keys.
2. Replace regex-only inspection with configurable DLP classifiers and structured-data/attachment inspection.
3. Sign audit checkpoints and export them to a separately administered append-only destination.
4. Add rate limits, TLS enforcement, key rotation, retention controls, backup/restore testing and alerting.
5. Add an Oracle adapter that exposes a fixed set of approved operations, with authorization enforced in Oracle as well as in the application.

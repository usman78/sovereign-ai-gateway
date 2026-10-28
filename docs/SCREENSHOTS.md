# Screenshot checklist

Capture screenshots after removing secrets and personal information. Save the approved images under `docs/images/` using the suggested filenames below. The README can then be updated to display them.

| Suggested filename | What to capture | Safety check |
|---|---|---|
| `dashboard-overview.png` | Connected Security & Activity Monitor showing KPI cards, gateway activity, event distribution and audit-chain status | No admin key visible in the field; no secret-bearing browser/network panels |
| `agent-oracle-success.png` | Successful `POST /v1/agent/chat` response for the synthetic IT department | Use only synthetic department data; redact bearer tokens and OAuth credentials |
| `policy-redact.png` | A prompt with synthetic `alice@example.com` showing a successful redacted response and `policy_action: redacted` | Never use a real person's email, CNIC, phone or credentials |
| `policy-block.png` | The same synthetic test under block mode returning HTTP 403 | Show only the response code and safe error detail; hide API keys |
| `unsupported-tool-rejected.png` | An unsupported salary/password request receiving the no-approved-operation response | Do not include real employee identifiers or records |
| `oracle-audit-correlation.png` | SQL Developer Web showing a synthetic `DEPARTMENT_SUMMARY` record with a gateway request ID | Hide workspace account details if desired; never show passwords or tokens |
| `tool-selection.png` | Gemma 4 native tool-call test selecting `department_summary` with `department_code: IT` | Ensure terminal output does not contain credentials |

## Adding the images to the README

After capturing, place the files in `docs/images/` and add image links in the README's screenshots section, for example:

```markdown
![Security dashboard](docs/images/dashboard-overview.png)
```

Do not commit `.env`, SQLite audit databases, OAuth credentials, bearer tokens, Postman environments containing secrets, or screenshots that expose them.

# Oracle integration boundary (design note)

The current runnable prototype does not connect to Oracle. This note defines the boundary for a future Oracle adapter and, importantly, what the LLM must **not** be allowed to do.

## Preferred interaction model

```text
User question
    ↓
Gateway authentication + prompt policy
    ↓
Intent/tool selection (allowlisted tool names only)
    ↓
Application authorization checks
    ↓
Oracle connection using a low-privilege service identity
    ↓
Approved PL/SQL package procedure
    ↓
Bound, validated parameters + bounded result set
    ↓
Gateway response policy + audit event
```

## Rules for the Oracle adapter

- Do not give an LLM an Oracle username/password, wallet, connection string or unrestricted SQL execution endpoint.
- Do not execute model-generated SQL with a schema owner, DBA account or broadly privileged application account.
- Map a small set of business intents to named, versioned operations, for example `get_department_headcount` or `get_monthly_expense_summary`.
- Expose those operations through a PL/SQL package with explicit parameters, input validation, bounded result sizes and predictable output types.
- Grant the gateway identity `EXECUTE` on the approved package rather than broad `SELECT` on application tables wherever practical.
- Enforce authorization in the application and again in the database where feasible. Never treat a role or employee identifier supplied by the model as proof of authorization.
- Use bind variables for all data values. Avoid dynamic SQL; where dynamic SQL is unavoidable, identifiers must come from a strict allowlist rather than model output.
- Record a correlation ID and authenticated actor through trusted application context/session metadata. Do not trust an arbitrary prompt field as the actor identity.
- Set useful Oracle session metadata (for example module/action/client identifier) so database-side auditing can be correlated with gateway events. Ensure pooled sessions are reset between borrowers.
- Keep database audit records under database-side controls. Gateway audit events complement Oracle auditing; they do not replace it.
- Return the minimum data needed to answer the question. Aggregate or mask sensitive columns before results reach the model.

## Example tool contract

A gateway tool registry could expose a contract such as:

```json
{
  "name": "get_department_headcount",
  "description": "Return the authorized headcount for one department.",
  "parameters": {
    "type": "object",
    "properties": {
      "department_code": { "type": "string", "maxLength": 12 }
    },
    "required": ["department_code"],
    "additionalProperties": false
  }
}
```

The gateway would validate the tool name and parameter schema, check the authenticated user's entitlement, and invoke a fixed PL/SQL procedure with bound parameters. The model never chooses a table name, SQL statement, database identity or privilege level.

## Questions to settle before implementation

- Which Oracle versions and authentication modes must be supported?
- Is the gateway deployed beside the database, on an application server, or in a separate on-premises segment?
- Which user identity must Oracle audit records represent: end user, service identity, or both?
- Which approved business operations and data classifications are in scope?
- Which database auditing features are already enabled and who owns their retention?

These decisions should be made with the Oracle DBA/security owner before a real database connection is added.

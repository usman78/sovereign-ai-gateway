from __future__ import annotations

import hmac
import logging
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse

from .ords_api import ORDSAPIError, ORDSOAuthError, _get_ords_client

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/admin/dashboard", tags=["Admin Monitoring Dashboard"])

_SAFE_DETAIL_KEYS = {
    "provider", "model", "model_provider", "policy_action", "sensitive_categories",
    "operation", "tool_name", "arguments", "department_code", "department_count",
    "error_type", "reason", "provider_contacted", "raw_prompt_logged", "elapsed_ms",
    "tool_executed", "requested_count", "response_sha256", "result_sha256",
}


def _require_dashboard_admin(request: Request, x_admin_key: str | None) -> str:
    settings = getattr(request.app.state, "settings", None)
    expected = getattr(settings, "admin_api_key", None) if settings is not None else None
    if not expected:
        raise HTTPException(status_code=503, detail={"code": "admin_auth_not_configured"})
    if not x_admin_key or not hmac.compare_digest(x_admin_key, expected):
        raise HTTPException(status_code=401, detail={"code": "invalid_or_missing_admin_key"})
    return "administrator"


def _store(request: Request) -> Any:
    store = getattr(request.app.state, "audit_store", None)
    if store is None:
        raise HTTPException(status_code=503, detail={"code": "audit_store_unavailable"})
    return store


def _safe_event(event: dict[str, Any]) -> dict[str, Any]:
    details = event.get("details") or {}
    if not isinstance(details, dict):
        details = {}
    safe_details = {key: details[key] for key in _SAFE_DETAIL_KEYS if key in details}
    event_type = str(event.get("event_type") or "unknown")

    labels: list[str] = []
    for key in ("tool_name", "operation", "department_code", "policy_action", "error_type", "reason"):
        value = safe_details.get(key)
        if value not in (None, ""):
            labels.append(f"{key}={value}")
    categories = safe_details.get("sensitive_categories")
    if isinstance(categories, dict) and categories:
        labels.append("sensitive=" + ", ".join(f"{k}:{v}" for k, v in categories.items()))

    return {
        "id": event.get("id"),
        "occurred_at": event.get("occurred_at"),
        "event_type": event_type,
        "actor": event.get("actor"),
        "request_id": event.get("request_id"),
        "summary": " · ".join(labels) if labels else event_type.replace(".", " "),
        "details": safe_details,
    }


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def _metrics(events: list[dict[str, Any]], integrity: dict[str, Any]) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    day_cutoff = now - timedelta(hours=24)
    week_cutoff = now - timedelta(days=7)
    by_type = Counter(str(event.get("event_type") or "unknown") for event in events)
    agent_starts = {
        "agent.requested", "agent.request.blocked", "agent.completed_without_tool"
    }
    agent_requests = sum(1 for event in events if event.get("event_type") in agent_starts)
    blocked = 0
    redacted = 0
    forwarded = 0
    for event in events:
        details = event.get("details") or {}
        event_type = str(event.get("event_type") or "")
        action = details.get("policy_action") if isinstance(details, dict) else None
        if event_type.endswith("blocked") or action == "blocked":
            blocked += 1
        if action == "redacted":
            redacted += 1
        if action == "forwarded":
            forwarded += 1
    parsed_times = [_parse_time(event.get("occurred_at")) for event in events]
    last_24h = sum(1 for value in parsed_times if value and value >= day_cutoff)
    last_7d = sum(1 for value in parsed_times if value and value >= week_cutoff)
    tool_success = by_type.get("agent.tool.succeeded", 0)
    tool_rejected = by_type.get("agent.tool.rejected", 0)
    failed_events = sum(
        count for name, count in by_type.items()
        if name.endswith(".failed") or name.endswith(".error")
    )
    return {
        "events_loaded": len(events),
        "agent_requests": agent_requests,
        "blocked_events": blocked,
        "redacted_requests": redacted,
        "forwarded_requests": forwarded,
        "tool_executions": tool_success,
        "tool_rejections": tool_rejected,
        "failed_events": failed_events,
        "events_last_24h": last_24h,
        "events_last_7d": last_7d,
        "event_types": dict(by_type),
        "audit_integrity": integrity,
        "generated_at": now.isoformat(),
        "window_note": "Counts are based on the latest 1,000 gateway audit events returned by the local audit store.",
    }


@router.get("", response_class=HTMLResponse, include_in_schema=False)
@router.get("/", response_class=HTMLResponse, include_in_schema=False)
async def dashboard_page() -> HTMLResponse:
    # This shell contains no operational data. All dashboard data APIs require X-Admin-Key.
    html = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>Sovereign AI Gateway · Security Monitor</title>
<style>
:root{--bg:#0b1220;--panel:#111d30;--panel2:#15243a;--line:#263a55;--text:#e8eef7;--muted:#96a8bd;--green:#57d6a1;--amber:#f2bd64;--red:#ff7d82;--blue:#81b7ff;--radius:15px}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(1200px 650px at 10% -10%,#183451 0%,transparent 55%),var(--bg);color:var(--text);font:14px/1.5 Inter,Segoe UI,system-ui,sans-serif}
main{max-width:1440px;margin:auto;padding:28px 24px 50px}.top{display:flex;justify-content:space-between;align-items:center;gap:20px;margin-bottom:24px}.brand{display:flex;align-items:center;gap:13px}.mark{width:43px;height:43px;border-radius:13px;background:linear-gradient(135deg,#1f9e79,#226e9e);display:grid;place-items:center;font-size:22px}.eyebrow{color:var(--green);font-size:11px;font-weight:800;letter-spacing:.16em;text-transform:uppercase}.title{font-size:24px;font-weight:760;letter-spacing:-.04em}.sub{color:var(--muted);font-size:12px}.status{border:1px solid var(--line);padding:8px 12px;border-radius:99px;color:var(--muted);font-size:12px}.dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--green);margin-right:7px}
.panel{background:linear-gradient(180deg,rgba(21,36,58,.96),rgba(15,27,44,.96));border:1px solid var(--line);border-radius:var(--radius);padding:18px;box-shadow:0 16px 50px rgba(0,0,0,.15)}.login{display:flex;align-items:end;gap:12px;flex-wrap:wrap;margin-bottom:20px}.login label{display:block;color:var(--muted);font-size:12px;margin-bottom:6px}.login .field{flex:1;min-width:250px}.login input,.filter input,.filter select{width:100%;background:#091423;border:1px solid var(--line);border-radius:9px;color:var(--text);padding:11px 12px;outline:none}.login input:focus,.filter input:focus,.filter select:focus{border-color:var(--blue)}button{border:0;border-radius:9px;background:var(--green);color:#08251c;font-weight:800;padding:11px 17px;cursor:pointer}button.secondary{background:#233b57;color:var(--text);border:1px solid var(--line)}button:hover{filter:brightness(1.08)}.message{color:var(--muted);font-size:12px;min-height:19px;margin-top:8px}.error{color:var(--red)}
.grid{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:13px;margin:18px 0}.metric{padding:16px;min-height:106px}.metric .label{color:var(--muted);font-size:12px}.metric .value{font-size:29px;letter-spacing:-.05em;font-weight:780;margin:5px 0}.metric .hint{color:var(--muted);font-size:11px}.green{color:var(--green)}.amber{color:var(--amber)}.red{color:var(--red)}
.layout{display:grid;grid-template-columns:1.25fr .75fr;gap:14px;margin-top:14px}.section-head{display:flex;justify-content:space-between;gap:12px;align-items:center;margin-bottom:14px}.section-title{font-size:15px;font-weight:750}.section-desc{color:var(--muted);font-size:11px}.tag{font-size:10px;border:1px solid var(--line);border-radius:99px;padding:4px 8px;color:var(--muted)}.integrity{display:flex;align-items:center;gap:12px;background:#0d1a2a;border:1px solid var(--line);border-radius:12px;padding:14px;margin-bottom:12px}.integrity .symbol{font-size:24px}.integrity strong{display:block}.barlist{display:grid;gap:10px}.barrow{display:grid;grid-template-columns:115px 1fr 32px;gap:9px;align-items:center;color:var(--muted);font-size:12px}.bar{background:#091423;height:8px;border-radius:9px;overflow:hidden}.bar i{display:block;height:100%;background:linear-gradient(90deg,#39a989,#70d6ad);border-radius:9px}.barrow b{color:var(--text);text-align:right}
.tablewrap{overflow:auto}table{border-collapse:collapse;width:100%;min-width:650px}th{text-align:left;color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.1em;font-weight:700;padding:10px;border-bottom:1px solid var(--line)}td{padding:11px 10px;border-bottom:1px solid rgba(38,58,85,.55);vertical-align:top;font-size:12px}tr:last-child td{border-bottom:0}.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:11px;color:#b5c8df}.event{font-weight:700}.pill{display:inline-block;padding:3px 7px;border-radius:99px;font-size:10px;font-weight:800;background:#20354d;color:var(--blue)}.pill.ok{background:#14372f;color:var(--green)}.pill.warn{background:#3c3020;color:var(--amber)}.pill.bad{background:#40252d;color:var(--red)}.filters{display:flex;gap:9px;flex-wrap:wrap;margin-bottom:12px}.filter{min-width:180px;flex:1}.empty{color:var(--muted);text-align:center;padding:25px}.foot{display:flex;justify-content:space-between;gap:10px;color:var(--muted);font-size:11px;margin-top:18px}
@media(max-width:1100px){.grid{grid-template-columns:repeat(3,1fr)}}@media(max-width:760px){main{padding:18px 12px}.top{align-items:flex-start}.layout{grid-template-columns:1fr}.grid{grid-template-columns:repeat(2,1fr)}.title{font-size:20px}}@media(max-width:420px){.grid{grid-template-columns:1fr 1fr}.metric .value{font-size:24px}}
</style></head><body><main>
<header class="top"><div class="brand"><div class="mark">⬡</div><div><div class="eyebrow">Sovereign AI Gateway</div><div class="title">Security & Activity Monitor</div><div class="sub">Local inference · Controlled Oracle access · Audit visibility</div></div></div><div class="status" id="status"><span class="dot"></span>Not connected</div></header>
<section class="panel"><div class="section-head"><div><div class="section-title">Administrator access</div><div class="section-desc">Enter the gateway ADMIN_API_KEY. It remains in this page's memory only.</div></div><span class="tag">Read-only dashboard</span></div><div class="login"><div class="field"><label for="adminKey">Gateway administrator key</label><input id="adminKey" type="password" autocomplete="off" placeholder="Paste ADMIN_API_KEY"></div><button id="connect">Connect dashboard</button><button class="secondary" id="disconnect">Disconnect</button></div><div id="message" class="message">Dashboard data endpoints require administrator authentication.</div></section>
<section class="grid" id="metrics"><article class="panel metric"><div class="label">Gateway events</div><div class="value">—</div><div class="hint">Latest audit records</div></article><article class="panel metric"><div class="label">Agent requests</div><div class="value">—</div><div class="hint">Natural-language requests</div></article><article class="panel metric"><div class="label">Blocked</div><div class="value red">—</div><div class="hint">Policy rejections</div></article><article class="panel metric"><div class="label">Redacted</div><div class="value amber">—</div><div class="hint">Prompts sanitized</div></article><article class="panel metric"><div class="label">Tool executions</div><div class="value green">—</div><div class="hint">Approved Oracle operations</div></article><article class="panel metric"><div class="label">Tool rejections</div><div class="value">—</div><div class="hint">Unapproved / invalid calls</div></article></section>
<section class="layout"><article class="panel"><div class="section-head"><div><div class="section-title">Gateway activity</div><div class="section-desc">Latest application audit events</div></div><button class="secondary" id="refresh">Refresh</button></div><div class="filters"><div class="filter"><input id="requestFilter" placeholder="Filter by request ID"></div><div class="filter"><select id="eventFilter"><option value="">All event types</option></select></div></div><div class="tablewrap"><table><thead><tr><th>Time</th><th>Event</th><th>Request ID</th><th>Actor</th><th>Summary</th></tr></thead><tbody id="gatewayRows"><tr><td colspan="5" class="empty">Connect to load gateway activity.</td></tr></tbody></table></div></article>
<aside class="panel"><div class="section-head"><div><div class="section-title">Audit integrity</div><div class="section-desc">SQLite hash-chain verification</div></div><span class="tag">SHA-256 chain</span></div><div class="integrity" id="integrity"><div class="symbol">◌</div><div><strong>Not checked</strong><div class="sub">Connect to verify the audit chain.</div></div></div><div class="section-title" style="margin:16px 0 12px">Event distribution</div><div class="barlist" id="distribution"><div class="empty">No metrics loaded.</div></div><div class="section-desc" id="windowNote" style="margin-top:15px">Counts reflect a bounded recent audit window.</div></aside></section>
<section class="panel" style="margin-top:14px"><div class="section-head"><div><div class="section-title">Oracle-side audit events</div><div class="section-desc">Records from AI_GATEWAY_AUDIT exposed through the protected ORDS audit endpoint</div></div><span class="tag" id="oracleStatus">Not loaded</span></div><div class="tablewrap"><table><thead><tr><th>Time</th><th>Operation</th><th>Department</th><th>Outcome</th><th>Gateway request ID</th><th>Actor</th></tr></thead><tbody id="oracleRows"><tr><td colspan="6" class="empty">Connect to load Oracle-side audit records.</td></tr></tbody></table></div><div class="section-desc" id="correlationNote" style="margin-top:12px">Correlation uses the shared gateway request ID. Older Oracle records created before the correlation migration will have no gateway request ID.</div></section>
<div class="foot"><span>Proof of concept · Synthetic department data</span><span id="updated">Not refreshed</span></div>
</main><script>
let adminKey='';let gatewayEvents=[];let oracleEvents=[];const $=id=>document.getElementById(id);
function setMessage(text,err=false){$('message').textContent=text;$('message').className='message'+(err?' error':'')}
function headers(){return {'X-Admin-Key':adminKey,'Accept':'application/json'}}
async function api(path){const r=await fetch(path,{headers:headers(),cache:'no-store'});let d={};try{d=await r.json()}catch{}if(!r.ok)throw new Error((d.detail&& (d.detail.code||d.detail))||('HTTP '+r.status));return d}
function safeText(v){return v===null||v===undefined?'—':String(v)}
function pill(value){const s=String(value||'').toLowerCase();let cls='pill';if(['success','succeeded','valid','forwarded'].includes(s))cls+=' ok';else if(['blocked','redacted','rejected','not_found'].includes(s))cls+=' warn';else if(['failed','error','invalid'].includes(s))cls+=' bad';return '<span class="'+cls+'">'+safeText(value)+'</span>'}
function addCell(tr,value,cls=''){const td=document.createElement('td');td.textContent=safeText(value);if(cls)td.className=cls;tr.appendChild(td)}
function renderMetrics(m){const vals=[m.events_loaded,m.agent_requests,m.blocked_events,m.redacted_requests,m.tool_executions,m.tool_rejections];$('metrics').querySelectorAll('.value').forEach((node,i)=>node.textContent=safeText(vals[i]));const integrity=m.audit_integrity||{};$('integrity').innerHTML='';const valid=integrity.valid===true;const symbol=document.createElement('div');symbol.className='symbol';symbol.textContent=valid?'✓':(integrity.valid===false?'!':'?');const body=document.createElement('div');const strong=document.createElement('strong');strong.textContent=valid?'Chain valid':(integrity.valid===false?'Integrity failure':'Unavailable');const detail=document.createElement('div');detail.className='sub';detail.textContent=(integrity.checked_events??0)+' events checked'+(integrity.first_invalid_event_id?' · first invalid ID '+integrity.first_invalid_event_id:'');body.append(strong,detail);$('integrity').append(symbol,body);const dist=$('distribution');dist.innerHTML='';const entries=Object.entries(m.event_types||{}).sort((a,b)=>b[1]-a[1]).slice(0,8);const max=Math.max(1,...entries.map(x=>x[1]));for(const [name,count] of entries){const row=document.createElement('div');row.className='barrow';const label=document.createElement('span');label.textContent=name;const bar=document.createElement('div');bar.className='bar';const fill=document.createElement('i');fill.style.width=(count/max*100)+'%';bar.append(fill);const n=document.createElement('b');n.textContent=count;row.append(label,bar,n);dist.append(row)}if(!entries.length)dist.textContent='No events recorded.';$('windowNote').textContent=m.window_note||'';$('updated').textContent='Updated '+new Date(m.generated_at).toLocaleString()}
function renderEvents(events){const body=$('gatewayRows');body.innerHTML='';if(!events.length){body.innerHTML='<tr><td colspan="5" class="empty">No matching gateway events.</td></tr>';return}for(const e of events){const tr=document.createElement('tr');addCell(tr,e.occurred_at);const event=document.createElement('td');event.className='event';event.textContent=e.event_type;tr.appendChild(event);addCell(tr,e.request_id,'mono');addCell(tr,e.actor);addCell(tr,e.summary);body.append(tr)}}
function renderOracle(events,correlatedIds=[]){const body=$('oracleRows');body.innerHTML='';if(!events.length){body.innerHTML='<tr><td colspan="6" class="empty">No Oracle audit records returned.</td></tr>';return}const ids=new Set(correlatedIds);let matched=0;for(const e of events){const tr=document.createElement('tr');addCell(tr,e.occurred_at);addCell(tr,e.operation_name);addCell(tr,e.department_code);const td=document.createElement('td');const badge=document.createElement('span');const outcome=String(e.outcome||'unknown');const normalized=outcome.toLowerCase();badge.className='pill'+(['success'].includes(normalized)?' ok':(['rejected','not_found'].includes(normalized)?' warn':(['error','failed'].includes(normalized)?' bad':'')));badge.textContent=outcome;td.append(badge);tr.append(td);const req=String(e.gateway_request_id||'');addCell(tr,req||'No correlation ID','mono');addCell(tr,e.actor);if(req&&ids.has(req))matched++;body.append(tr)}$('correlationNote').textContent=matched+' of '+events.length+' Oracle audit rows correlate with gateway audit request IDs. Existing older rows may not have a correlation ID.'}
function applyFilters(){const request=$('requestFilter').value.trim().toLowerCase();const type=$('eventFilter').value;renderEvents(gatewayEvents.filter(e=>(!request||String(e.request_id||'').toLowerCase().includes(request))&&(!type||e.event_type===type)))}
function populateFilters(events){const select=$('eventFilter');const old=select.value;select.innerHTML='<option value="">All event types</option>';[...new Set(events.map(e=>e.event_type))].sort().forEach(v=>{const op=document.createElement('option');op.value=v;op.textContent=v;select.append(op)});select.value=old}
async function load(){if(!adminKey){setMessage('Enter the administrator key first.',true);return}setMessage('Loading gateway and Oracle audit data…');try{const [overview,eventData]=await Promise.all([api('/admin/dashboard/api/overview'),api('/admin/dashboard/api/events?limit=200')]);renderMetrics(overview);gatewayEvents=eventData.events||[];populateFilters(gatewayEvents);applyFilters();try{const oracle=await api('/admin/dashboard/api/oracle-audit');oracleEvents=oracle.items||[];renderOracle(oracleEvents,oracle.correlated_request_ids||[]);$('oracleStatus').textContent=oracle.available?'Connected · '+oracleEvents.length+' rows':'Unavailable'}catch(err){oracleEvents=[];renderOracle([]);$('oracleStatus').textContent='Unavailable';$('correlationNote').textContent='Could not load Oracle audit events: '+err.message}const valid=overview.audit_integrity&&overview.audit_integrity.valid===true;$('status').innerHTML='<span class="dot"></span>Connected · '+(valid?'Audit valid':'Review audit status');setMessage('Dashboard loaded. Gateway activity and Oracle audit data are read-only.')}catch(err){$('status').textContent='Not connected';setMessage('Unable to load dashboard: '+err.message,true)}}
$('connect').addEventListener('click',async()=>{adminKey=$('adminKey').value.trim();await load()});$('disconnect').addEventListener('click',()=>{adminKey='';$('adminKey').value='';gatewayEvents=[];oracleEvents=[];$('status').textContent='Disconnected';setMessage('Administrator key cleared from page memory.');renderEvents([]);renderOracle([])});$('refresh').addEventListener('click',load);$('eventFilter').addEventListener('change',applyFilters);$('requestFilter').addEventListener('input',applyFilters);</script></body></html>'''
    response = HTMLResponse(html)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@router.get("/api/overview")
async def dashboard_overview(request: Request, x_admin_key: str | None = Header(default=None)) -> dict[str, Any]:
    _require_dashboard_admin(request, x_admin_key)
    store = _store(request)
    events = store.list_events(limit=1000)
    integrity = store.verify()
    return _metrics(events, integrity)


@router.get("/api/events")
async def dashboard_events(
    request: Request,
    limit: int = Query(default=200, ge=1, le=500),
    event_type: str | None = Query(default=None, max_length=100),
    request_id: str | None = Query(default=None, max_length=80),
    x_admin_key: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_dashboard_admin(request, x_admin_key)
    events = [_safe_event(event) for event in _store(request).list_events(limit=limit)]
    if event_type:
        events = [event for event in events if event["event_type"] == event_type]
    if request_id:
        events = [event for event in events if event.get("request_id") == request_id]
    return {"count": len(events), "events": events}


@router.get("/api/oracle-audit")
async def dashboard_oracle_audit(
    request: Request,
    x_admin_key: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_dashboard_admin(request, x_admin_key)
    client = _get_ords_client(request)
    try:
        items = await client.list_audit_events()
    except ORDSOAuthError as exc:
        logger.warning("Dashboard could not authenticate to ORDS audit endpoint: %s", type(exc).__name__)
        raise HTTPException(status_code=502, detail={"code": "dashboard_ords_oauth_failed"}) from exc
    except ORDSAPIError as exc:
        logger.warning("Dashboard ORDS audit endpoint failed: code=%s status=%s", exc.code, exc.status_code)
        raise HTTPException(status_code=502, detail={"code": exc.code, "upstream_status": exc.status_code}) from exc
    gateway_events = _store(request).list_events(limit=1000)
    gateway_request_ids = {str(event.get("request_id")) for event in gateway_events if event.get("request_id")}
    correlated_ids = sorted({
        str(item.get("gateway_request_id"))
        for item in items
        if item.get("gateway_request_id") and str(item.get("gateway_request_id")) in gateway_request_ids
    })
    return {
        "available": True,
        "count": len(items),
        "items": items,
        "correlated_request_ids": correlated_ids,
        "correlated_count": len(correlated_ids),
    }


@router.get("/api/correlation")
async def dashboard_correlation(
    request: Request,
    x_admin_key: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_dashboard_admin(request, x_admin_key)
    gateway_events = _store(request).list_events(limit=1000)
    client = _get_ords_client(request)
    try:
        oracle_events = await client.list_audit_events()
    except (ORDSOAuthError, ORDSAPIError) as exc:
        raise HTTPException(status_code=502, detail={"code": "oracle_audit_unavailable"}) from exc

    gateway_by_request: dict[str, list[dict[str, Any]]] = {}
    for event in gateway_events:
        request_id = event.get("request_id")
        if request_id:
            gateway_by_request.setdefault(str(request_id), []).append(event)

    matched: list[dict[str, Any]] = []
    unmatched: list[dict[str, Any]] = []
    for event in oracle_events:
        request_id = event.get("gateway_request_id")
        if request_id and request_id in gateway_by_request:
            matched.append({"oracle_event": event, "gateway_events": [_safe_event(e) for e in gateway_by_request[request_id]]})
        else:
            unmatched.append(event)
    return {
        "matched_count": len(matched),
        "unmatched_oracle_count": len(unmatched),
        "matched": matched,
        "unmatched_oracle_events": unmatched,
    }

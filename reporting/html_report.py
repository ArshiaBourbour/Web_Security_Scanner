from __future__ import annotations

import html
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from config import REPORT_DIR
from core.result import CheckResult

STEP_TITLES = {
    "ssl": "SSL Information",
    "headers": "HTTP Security Headers",
    "dns": "DNS Records",
    "whois": "WHOIS Information",
    "html": "HTML Analysis",
    "technology": "Technology Detection",
    "cookies": "Cookie Security Analysis",
    "http_methods": "HTTP Methods Scan",
    "robots": "robots.txt Scan",
    "sitemap": "sitemap.xml Scan",
    "csp": "CSP Analysis",
    "cors": "CORS Analysis",
    "hsts": "HSTS Analysis",
    "clickjacking": "Clickjacking Detection",
    "directory_listing": "Directory Listing Detection",
}


def _esc(value: Any) -> str:
    # every dynamic value originates from a scanned third-party site, so escape it
    if value is None:
        return "-"
    return html.escape(str(value))


def _kv_table(rows: list[tuple[str, Any]]) -> str:
    body = "".join(
        f"<tr><th>{_esc(k)}</th><td>{_esc(v) if v not in (None, '') else '-'}</td></tr>"
        for k, v in rows
    )
    return f"<table class='kv'>{body}</table>"


def _issues_table(issues: list[dict[str, str]]) -> str:
    if not issues:
        return "<p class='ok'>No issues detected.</p>"

    rows = "".join(
        f"<tr><td><span class='sev sev-{_esc(i['severity']).lower()}'>{_esc(i['severity'])}</span></td>"
        f"<td>{_esc(i['title'])}</td><td>{_esc(i['detail'])}</td></tr>"
        for i in issues
    )
    return (
        "<table class='data'><thead><tr><th>Severity</th><th>Issue</th>"
        f"<th>Detail</th></tr></thead><tbody>{rows}</tbody></table>"
    )


def _empty(message: str) -> str:
    return f"<p class='dim'>{_esc(message)}</p>"


def _render_ssl(r: CheckResult) -> str:
    if r.failed:
        return f"<p class='error'>SSL check failed: {_esc(r.error)}</p>"
    d = r.data
    if not d:
        return _empty("No SSL data available.")
    return _kv_table(
        [
            ("Subject", d.get("subject")),
            ("Issuer", d.get("issuer")),
            ("Valid From", d.get("notBefore")),
            ("Valid Until", d.get("notAfter")),
            ("Version", d.get("version")),
            ("Serial Number", d.get("serialNumber")),
            ("SAN", d.get("san")),
        ]
    )


def _render_headers(r: CheckResult) -> str:
    if r.failed:
        return f"<p class='error'>Header check failed: {_esc(r.error)}</p>"
    d = r.data
    if not d:
        return _empty("No header data available.")
    rows = [("Server", d.get("server"))] + list(d.get("security_headers", {}).items())
    return _kv_table(rows)


def _render_dns(r: CheckResult) -> str:
    if r.failed:
        return f"<p class='error'>DNS check failed: {_esc(r.error)}</p>"
    d = r.data
    if not d:
        return _empty("No DNS data available.")
    rows = []
    for record_type in ("A", "AAAA", "MX", "NS", "TXT"):
        values = d.get(record_type) or []
        rows.append((record_type, ", ".join(values) if values else "none found"))
    return _kv_table(rows)


def _render_whois(r: CheckResult) -> str:
    if r.failed:
        return f"<p class='error'>WHOIS check failed: {_esc(r.error)}</p>"
    d = r.data
    if not d:
        return _empty("No WHOIS data available.")
    return _kv_table(
        [
            ("Registrar", d.get("registrar")),
            ("Creation Date", d.get("creation_date")),
            ("Expiration Date", d.get("expiration_date")),
            ("Name Servers", d.get("name_servers")),
        ]
    )


def _render_html(r: CheckResult) -> str:
    if r.failed:
        return f"<p class='error'>HTML check failed: {_esc(r.error)}</p>"
    d = r.data
    if not d:
        return _empty("No HTML data available.")
    return _kv_table(
        [
            ("Script Tags", d.get("script_count")),
            ("Iframe Tags", d.get("iframe_count")),
            ("Form Tags", d.get("form_count")),
            ("External Links", d.get("external_links")),
        ]
    )


def _render_technology(r: CheckResult) -> str:
    if r.failed:
        return f"<p class='error'>Technology detection failed: {_esc(r.error)}</p>"
    d = r.data
    if not d:
        return _empty("No technologies detected.")
    technologies = d.get("technologies", d)
    rows = [(k.title(), ", ".join(v)) for k, v in technologies.items() if v]
    if not rows:
        return _empty("No technologies detected.")
    return _kv_table(rows)


def _render_cookies(r: CheckResult) -> str:
    if r.failed:
        return f"<p class='error'>Cookie check failed: {_esc(r.error)}</p>"
    d = r.data
    if not d:
        return _empty("No cookies were set by the target.")

    def flag(v: bool) -> str:
        return "<span class='ok'>yes</span>" if v else "<span class='bad'>no</span>"

    def samesite_cell(c: dict) -> str:
        if c["samesite"]:
            return _esc(c["samesite"])
        return "<span class='bad'>none</span>"

    rows = "".join(
        f"<tr><td>{_esc(c['name'])}</td><td>{flag(c['secure'])}</td>"
        f"<td>{flag(c['http_only'])}</td>"
        f"<td>{samesite_cell(c)}</td>"
        f"<td>{_esc(c['domain'])}</td>"
        f"<td>{'Session' if c['session_cookie'] else 'Persistent'}</td></tr>"
        for c in d.get("cookies", [])
    )
    table = (
        "<table class='data'><thead><tr><th>Name</th><th>Secure</th><th>HttpOnly</th>"
        f"<th>SameSite</th><th>Domain</th><th>Type</th></tr></thead><tbody>{rows}</tbody></table>"
    )
    summary = (
        f"<p>Total: {d['total']} &nbsp; Insecure: {d['insecure_count']} &nbsp; "
        f"Missing HttpOnly: {d['no_httponly_count']} &nbsp; Missing SameSite: {d['no_samesite_count']}</p>"
    )
    return table + summary


def _render_http_methods(r: CheckResult) -> str:
    if r.failed:
        return f"<p class='error'>HTTP methods check failed: {_esc(r.error)}</p>"
    d = r.data
    if not d:
        return _empty("No HTTP methods could be determined.")

    labels = {
        "allowed": "<span class='ok'>allowed</span>",
        "disallowed": "<span class='dim'>not allowed</span>",
        "unknown": "<span class='warn'>unclear</span>",
        "unreachable": "<span class='dim'>no response</span>",
    }
    rows = "".join(
        f"<tr><td>{_esc(e['method'])}</td><td>{_esc(e['status'])}</td>"
        f"<td>{labels.get(e['classification'], _esc(e['classification']))}</td></tr>"
        for e in d.get("results", [])
    )
    table = (
        "<table class='data'><thead><tr><th>Method</th><th>Status</th>"
        f"<th>Result</th></tr></thead><tbody>{rows}</tbody></table>"
    )
    notes = ""
    if d.get("trace_enabled"):
        if d.get("trace_reflects_body"):
            notes += "<p class='bad'>TRACE is enabled and reflects request data (possible XST risk).</p>"
        else:
            notes += "<p class='warn'>TRACE method is enabled on this server.</p>"
    if d.get("risky_methods"):
        notes += (
            f"<p>Confirmed risky methods: {_esc(', '.join(d['risky_methods']))}</p>"
        )
    else:
        notes += "<p class='ok'>No risky HTTP methods were confirmed as enabled.</p>"
    return table + notes


def _render_robots(r: CheckResult) -> str:
    if r.failed:
        return f"<p class='error'>robots.txt check failed: {_esc(r.error)}</p>"
    d = r.data
    if not d:
        return _empty("No robots.txt data available.")
    if not d.get("found"):
        return _empty(f"No robots.txt found (status: {d.get('status_code')}).")

    out = _kv_table(
        [
            ("User-agents referenced", ", ".join(d["user_agents"]) or "none"),
            ("Disallowed paths", len(d["disallowed_paths"])),
            ("Allowed paths", len(d["allowed_paths"])),
            ("Crawl-delay", d.get("crawl_delay")),
        ]
    )
    if d.get("sitemaps"):
        out += "<p><strong>Sitemaps:</strong></p><ul>"
        out += "".join(f"<li>{_esc(s)}</li>" for s in d["sitemaps"])
        out += "</ul>"
    if d.get("sensitive_paths"):
        out += "<p class='warn'>Potentially sensitive disallowed paths:</p><ul>"
        out += "".join(f"<li>{_esc(p)}</li>" for p in d["sensitive_paths"])
        out += "</ul>"
    else:
        out += "<p class='ok'>No obviously sensitive paths found.</p>"
    return out


def _render_sitemap(r: CheckResult) -> str:
    if r.failed:
        return f"<p class='error'>sitemap.xml check failed: {_esc(r.error)}</p>"
    d = r.data
    if not d:
        return _empty("No sitemap.xml data available.")
    if not d.get("found"):
        return _empty("No sitemap.xml could be found.")

    def status_cell(s: dict) -> str:
        return _esc(200 if s.get("found") else s.get("status_code"))

    rows = "".join(
        f"<tr><td>{_esc(s['url'])}</td>"
        f"<td>{status_cell(s)}</td>"
        f"<td>{_esc(s.get('type', '-'))}</td>"
        f"<td>{_esc(s.get('entry_count', '-'))}</td></tr>"
        for s in d.get("sources", [])
    )
    out = (
        "<table class='data'><thead><tr><th>URL</th><th>Status</th><th>Type</th>"
        f"<th>Entries</th></tr></thead><tbody>{rows}</tbody></table>"
        f"<p>Total unique URLs discovered: {d['total_urls']}</p>"
    )
    sensitive = d.get("sensitive_urls", [])
    if sensitive:
        limit = 20
        out += "<p class='warn'>Potentially sensitive URLs:</p><ul>"
        out += "".join(f"<li>{_esc(u)}</li>" for u in sensitive[:limit])
        out += "</ul>"
        if len(sensitive) > limit:
            out += (
                f"<p class='dim'>+{len(sensitive) - limit} more matched, likely "
                "coincidental keyword matches rather than real findings.</p>"
            )
    else:
        out += "<p class='ok'>No obviously sensitive URLs found.</p>"
    return out


def _render_csp(r: CheckResult) -> str:
    if r.failed:
        return f"<p class='error'>CSP check failed: {_esc(r.error)}</p>"
    d = r.data
    if not d or not d.get("found"):
        return "<p class='bad'>No Content-Security-Policy header present.</p>"

    out = ""
    if d.get("report_only"):
        out += "<p class='warn'>Policy is enforced via Report-Only header (not blocking).</p>"
    out += f"<p class='raw'>{_esc(d['raw'])}</p>"
    rows = [
        (k, " ".join(v) if v else "(empty)") for k, v in d.get("directives", {}).items()
    ]
    out += _kv_table(rows)
    out += _issues_table(d.get("issues", []))
    return out


def _render_cors(r: CheckResult) -> str:
    if r.failed:
        return f"<p class='error'>CORS check failed: {_esc(r.error)}</p>"
    d = r.data
    if not d or not d.get("found"):
        return "<p class='ok'>No CORS headers present — default same-origin policy applies.</p>"

    out = f"<p class='dim'>Test Origin used: {_esc(d['test_origin'])}</p>"
    out += _kv_table(
        [
            ("Access-Control-Allow-Origin", d.get("allow_origin")),
            ("Access-Control-Allow-Credentials", d.get("allow_credentials")),
            ("Access-Control-Allow-Methods", d.get("allow_methods")),
            ("Access-Control-Allow-Headers", d.get("allow_headers")),
        ]
    )
    out += _issues_table(d.get("issues", []))
    return out


def _render_hsts(r: CheckResult) -> str:
    if r.failed:
        return f"<p class='error'>HSTS check failed: {_esc(r.error)}</p>"
    d = r.data
    if not d or not d.get("found"):
        return "<p class='bad'>No Strict-Transport-Security header present.</p>"

    out = f"<p class='raw'>{_esc(d['raw'])}</p>"
    out += _kv_table(
        [
            ("max-age", d.get("max_age")),
            ("includeSubDomains", d.get("include_subdomains")),
            ("preload", d.get("preload")),
        ]
    )
    out += _issues_table(d.get("issues", []))
    return out


def _render_clickjacking(r: CheckResult) -> str:
    if r.failed:
        return f"<p class='error'>Clickjacking check failed: {_esc(r.error)}</p>"
    d = r.data
    if not d:
        return _empty("No clickjacking data available.")

    out = _kv_table(
        [
            ("X-Frame-Options", d.get("x_frame_options")),
            ("CSP frame-ancestors", d.get("frame_ancestors")),
            ("Protected", d.get("protected")),
            ("Protection source", d.get("protection_source")),
        ]
    )
    out += _issues_table(d.get("issues", []))
    return out


def _render_directory_listing(r: CheckResult) -> str:
    if r.failed:
        return f"<p class='error'>Directory listing check failed: {_esc(r.error)}</p>"
    d = r.data
    if not d or not d.get("found"):
        return "<p class='ok'>No open directory listings found on common paths.</p>"

    out = "<ul>" + "".join(f"<li>{_esc(p)}</li>" for p in d["listings"]) + "</ul>"
    out += "<p class='warn'>These directories return a browsable file listing.</p>"
    return out


SECTION_RENDERERS = {
    "ssl": _render_ssl,
    "headers": _render_headers,
    "dns": _render_dns,
    "whois": _render_whois,
    "html": _render_html,
    "technology": _render_technology,
    "cookies": _render_cookies,
    "http_methods": _render_http_methods,
    "robots": _render_robots,
    "sitemap": _render_sitemap,
    "csp": _render_csp,
    "cors": _render_cors,
    "hsts": _render_hsts,
    "clickjacking": _render_clickjacking,
    "directory_listing": _render_directory_listing,
}


def _default_result(step: str) -> CheckResult:
    from core.result import CheckStatus

    return CheckResult(name=step, status=CheckStatus.ERROR, error="step did not run")


def _render_findings_table(findings: list[dict[str, str]]) -> str:
    if not findings:
        return "<p class='ok'>No issues found.</p>"
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    ordered = sorted(findings, key=lambda f: order.get(f["severity"], 3))
    rows = "".join(
        f"<tr><td><span class='sev sev-{_esc(f['severity']).lower()}'>{_esc(f['severity'])}</span></td>"
        f"<td>{_esc(f['title'])}</td><td>{_esc(f['recommendation'])}</td></tr>"
        for f in ordered
    )
    return (
        "<table class='data'><thead><tr><th>Severity</th><th>Finding</th>"
        f"<th>Recommendation</th></tr></thead><tbody>{rows}</tbody></table>"
    )


CSS = """
:root {
  --bg: #0d1117; --panel: #161b22; --border: #30363d;
  --text: #c9d1d9; --muted: #8b949e; --accent: #58a6ff;
  --high: #f85149; --medium: #d29922; --low: #58a6ff; --ok: #3fb950;
}
* { box-sizing: border-box; }
body { background: var(--bg); color: var(--text); font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 2rem; }
h1 { color: var(--accent); margin-bottom: 0.25rem; }
h2 { border-bottom: 1px solid var(--border); padding-bottom: 0.4rem; margin-top: 2.5rem; }
.meta { color: var(--muted); margin-bottom: 2rem; }
.summary { display: flex; gap: 2rem; align-items: center; background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; }
.score-badge { font-size: 2.5rem; font-weight: bold; }
.grade-Aplus, .grade-A { color: var(--ok); }
.grade-B { color: var(--medium); }
.grade-C, .grade-F { color: var(--high); }
table.kv, table.data { border-collapse: collapse; width: 100%; margin: 0.75rem 0; }
table.kv th, table.kv td, table.data th, table.data td { border: 1px solid var(--border); padding: 0.5rem 0.75rem; text-align: left; vertical-align: top; }
table.kv th { width: 240px; color: var(--muted); font-weight: 600; }
table.data th { background: var(--panel); color: var(--muted); }
.section { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem 1.5rem; margin-top: 1rem; }
.sev { padding: 0.15rem 0.5rem; border-radius: 4px; font-weight: 600; font-size: 0.85rem; }
.sev-high { background: rgba(248,81,73,0.15); color: var(--high); }
.sev-medium { background: rgba(210,153,34,0.15); color: var(--medium); }
.sev-low { background: rgba(88,166,255,0.15); color: var(--low); }
.ok { color: var(--ok); }
.bad { color: var(--high); }
.warn { color: var(--medium); }
.dim { color: var(--muted); }
.error { color: var(--high); }
.raw { font-family: monospace; background: #010409; padding: 0.75rem; border-radius: 4px; word-break: break-all; }
footer { color: var(--muted); margin-top: 3rem; font-size: 0.85rem; }
"""


def generate_html_report(
    target: str,
    results: dict[str, CheckResult],
    analysis: dict[str, Any],
    score: dict[str, Any],
    steps: list[str],
) -> str:
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    grade_class = "grade-" + score["grade"].replace("+", "plus")

    sections = ""
    for step in steps:
        result = results.get(step, _default_result(step))
        renderer = SECTION_RENDERERS.get(step)
        body = (
            renderer(result)
            if renderer
            else _empty("No renderer available for this check.")
        )
        title = STEP_TITLES.get(step, step)
        sections += f"<div class='section'><h2>{_esc(title)}</h2>{body}</div>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>4EYEZ Security Report — {_esc(target)}</title>
<style>{CSS}</style>
</head>
<body>
<h1>4EYEZ Web Security Report</h1>
<p class="meta">Target: <strong>{_esc(target)}</strong> &nbsp;|&nbsp; Generated: {_esc(generated_at)}</p>

<div class="summary">
  <div class="score-badge {grade_class}">{score["score"]}/100 ({_esc(score["grade"])})</div>
  <div>
    <p>Overall Risk: <strong>{_esc(score["risk"])}</strong></p>
    <p>High: {score["high"]} &nbsp; Medium: {score["medium"]} &nbsp; Low: {score["low"]}</p>
  </div>
</div>

<h2>Risk Analysis</h2>
{_render_findings_table(analysis["findings"])}

{sections}

<footer>Generated by 4EYEZ Web Security Scanner. For authorized security testing only.</footer>
</body>
</html>"""


def _safe_filename(target: str) -> str:
    # turn a target URL into a filesystem-safe report filename
    from urllib.parse import urlparse

    parsed = urlparse(target)
    host = parsed.netloc or parsed.path or target
    safe_host = re.sub(r"[^a-zA-Z0-9.-]", "_", host)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{safe_host}_{timestamp}.html"


def save_html_report(
    target: str,
    results: dict[str, CheckResult],
    analysis: dict[str, Any],
    score: dict[str, Any],
    steps: list[str],
) -> Path:
    content = generate_html_report(target, results, analysis, score, steps)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    path = REPORT_DIR / _safe_filename(target)
    path.write_text(content, encoding="utf-8")
    return path

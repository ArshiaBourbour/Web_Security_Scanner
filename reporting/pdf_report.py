from __future__ import annotations
from reporting.executive_summary import generate_executive_summary


from datetime import datetime
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape as xml_escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from config import REPORT_DIR
from core.report_naming import safe_report_filename
from core.result import CheckResult, CheckStatus
from reporting.html_report import STEP_TITLES

SEVERITY_COLORS = {
    "HIGH": colors.HexColor("#c0392b"),
    "MEDIUM": colors.HexColor("#b8860b"),
    "LOW": colors.HexColor("#2f6fb0"),
}

GRADE_COLORS = {
    "A+": "#2e7d32",
    "A": "#2e7d32",
    "B": "#b8860b",
    "C": "#c0392b",
    "F": "#c0392b",
}

_styles = getSampleStyleSheet()
_styles.add(
    ParagraphStyle(
        "SectionHeading", parent=_styles["Heading2"], spaceBefore=18, spaceAfter=6
    )
)
_styles.add(
    ParagraphStyle(
        "Mono", parent=_styles["Normal"], fontName="Courier", fontSize=8, leading=10
    )
)
_styles.add(ParagraphStyle("Small", parent=_styles["Normal"], fontSize=9, leading=12))
_styles.add(
    ParagraphStyle("Ok", parent=_styles["Small"], textColor=colors.HexColor("#2e7d32"))
)
_styles.add(
    ParagraphStyle("Bad", parent=_styles["Small"], textColor=colors.HexColor("#c0392b"))
)
_styles.add(
    ParagraphStyle(
        "Warn", parent=_styles["Small"], textColor=colors.HexColor("#b8860b")
    )
)
_styles.add(ParagraphStyle("Dim", parent=_styles["Small"], textColor=colors.grey))

TABLE_STYLE = TableStyle(
    [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c2f33")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        (
            "ROWBACKGROUNDS",
            (0, 1),
            (-1, -1),
            [colors.white, colors.HexColor("#f5f5f5")],
        ),
    ]
)

KV_STYLE = TableStyle(
    [
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f5f5f5")),
    ]
)


def _break_long_tokens(text: str, max_run: int = 40) -> str:
    out = []
    run = 0
    for ch in text:
        out.append(ch)
        if ch.isspace():
            run = 0
        else:
            run += 1
            if run >= max_run:
                out.append("\u200b")
                run = 0
    return "".join(out)


def _ptext(text: str, style: str = "Small") -> Paragraph:
    return Paragraph(_break_long_tokens(xml_escape(str(text))), _styles[style])


def _p(value: Any, style: str = "Small") -> Paragraph:
    if value is None or value == "":
        text = "-"
    else:
        text = xml_escape(str(_truncate(value, limit=500)))
    return Paragraph(_break_long_tokens(text), _styles[style])


def _kv_table(rows: list[tuple[str, Any]]) -> Table:
    data = [[_p(k), _p(v)] for k, v in rows]
    table = Table(data, colWidths=[1.8 * inch, 4.2 * inch])
    table.setStyle(KV_STYLE)
    return table


def _issues_table(issues: list[dict[str, str]]) -> list:
    if not issues:
        return [Paragraph("No issues detected.", _styles["Ok"])]

    data = [["Severity", "Issue", "Detail"]]
    for i in issues:
        data.append([_p(i["severity"]), _p(i["title"]), _p(i["detail"])])
    table = Table(data, colWidths=[0.8 * inch, 2 * inch, 3.2 * inch], repeatRows=1)
    table.setStyle(TABLE_STYLE)
    return [table]


def _empty(message: str) -> list:
    return [_ptext(message, "Dim")]


def _render_ssl(r: CheckResult) -> list:
    if r.failed:
        return [_ptext(f"SSL check failed: {r.error}", "Bad")]
    d = r.data
    if not d:
        return _empty("No SSL data available.")
    return [
        _kv_table(
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
    ]


def _truncate(value: Any, limit: int = 300) -> Any:
    text = str(value)
    if len(text) <= limit:
        return value
    return f"{text[:limit]}... ({len(text)} chars total, see full section below)"


def _render_headers(r: CheckResult) -> list:
    if r.failed:
        return [_ptext(f"Header check failed: {r.error}", "Bad")]
    d = r.data
    if not d:
        return _empty("No header data available.")
    rows = [("Server", d.get("server"))] + [
        (k, _truncate(v)) for k, v in d.get("security_headers", {}).items()
    ]
    return [_kv_table(rows)]


def _render_dns(r: CheckResult) -> list:
    if r.failed:
        return [_ptext(f"DNS check failed: {r.error}", "Bad")]
    d = r.data
    if not d:
        return _empty("No DNS data available.")
    rows = []
    for record_type in ("A", "AAAA", "MX", "NS", "TXT"):
        values = d.get(record_type) or []
        rows.append((record_type, ", ".join(values) if values else "none found"))
    return [_kv_table(rows)]


def _render_whois(r: CheckResult) -> list:
    if r.failed:
        return [_ptext(f"WHOIS check failed: {r.error}", "Bad")]
    d = r.data
    if not d:
        return _empty("No WHOIS data available.")
    return [
        _kv_table(
            [
                ("Registrar", d.get("registrar")),
                ("Creation Date", d.get("creation_date")),
                ("Expiration Date", d.get("expiration_date")),
                ("Name Servers", d.get("name_servers")),
            ]
        )
    ]


def _render_html(r: CheckResult) -> list:
    if r.failed:
        return [_ptext(f"HTML check failed: {r.error}", "Bad")]
    d = r.data
    if not d:
        return _empty("No HTML data available.")
    return [
        _kv_table(
            [
                ("Script Tags", d.get("script_count")),
                ("Iframe Tags", d.get("iframe_count")),
                ("Form Tags", d.get("form_count")),
                ("External Links", d.get("external_links")),
            ]
        )
    ]


def _render_technology(r: CheckResult) -> list:
    if r.failed:
        return [_ptext(f"Technology detection failed: {r.error}", "Bad")]
    d = r.data
    if not d:
        return _empty("No technologies detected.")
    technologies = d.get("technologies", d)
    rows = [(k.title(), ", ".join(v)) for k, v in technologies.items() if v]
    if not rows:
        return _empty("No technologies detected.")
    return [_kv_table(rows)]


def _render_cookies(r: CheckResult) -> list:
    if r.failed:
        return [_ptext(f"Cookie check failed: {r.error}", "Bad")]
    d = r.data
    if not d:
        return _empty("No cookies were set by the target.")

    data = [["Name", "Secure", "HttpOnly", "SameSite", "Domain", "Type"]]
    for c in d.get("cookies", []):
        data.append(
            [
                _p(c["name"]),
                _p("yes" if c["secure"] else "no"),
                _p("yes" if c["http_only"] else "no"),
                _p(c["samesite"] or "none"),
                _p(c["domain"]),
                _p("Session" if c["session_cookie"] else "Persistent"),
            ]
        )
    table = Table(
        data,
        repeatRows=1,
        colWidths=[
            1.1 * inch,
            0.6 * inch,
            0.7 * inch,
            0.8 * inch,
            1.3 * inch,
            0.9 * inch,
        ],
    )
    table.setStyle(TABLE_STYLE)

    summary = Paragraph(
        f"Total: {d['total']} &nbsp; Insecure: {d['insecure_count']} &nbsp; "
        f"Missing HttpOnly: {d['no_httponly_count']} &nbsp; Missing SameSite: {d['no_samesite_count']}",
        _styles["Small"],
    )
    return [table, Spacer(1, 6), summary]


def _render_http_methods(r: CheckResult) -> list:
    if r.failed:
        return [_ptext(f"HTTP methods check failed: {r.error}", "Bad")]
    d = r.data
    if not d:
        return _empty("No HTTP methods could be determined.")

    data = [["Method", "Status", "Result"]]
    for e in d.get("results", []):
        data.append([_p(e["method"]), _p(e["status"]), _p(e["classification"])])
    table = Table(data, repeatRows=1, colWidths=[1.5 * inch, 1.5 * inch, 3 * inch])
    table.setStyle(TABLE_STYLE)

    notes = []
    if d.get("trace_enabled"):
        if d.get("trace_reflects_body"):
            notes.append(
                Paragraph(
                    "TRACE is enabled and reflects request data (possible XST risk).",
                    _styles["Bad"],
                )
            )
        else:
            notes.append(
                Paragraph("TRACE method is enabled on this server.", _styles["Warn"])
            )
    if d.get("risky_methods"):
        notes.append(
            _ptext(f"Confirmed risky methods: {', '.join(d['risky_methods'])}", "Small")
        )
    else:
        notes.append(
            Paragraph("No risky HTTP methods were confirmed as enabled.", _styles["Ok"])
        )
    return [table, Spacer(1, 6)] + notes


def _render_robots(r: CheckResult) -> list:
    if r.failed:
        return [_ptext(f"robots.txt check failed: {r.error}", "Bad")]
    d = r.data
    if not d:
        return _empty("No robots.txt data available.")
    if not d.get("found"):
        return _empty(f"No robots.txt found (status: {d.get('status_code')}).")

    flow = [
        _kv_table(
            [
                ("User-agents referenced", ", ".join(d["user_agents"]) or "none"),
                ("Disallowed paths", len(d["disallowed_paths"])),
                ("Allowed paths", len(d["allowed_paths"])),
                ("Crawl-delay", d.get("crawl_delay")),
            ]
        )
    ]
    if d.get("sensitive_paths"):
        flow.append(Spacer(1, 6))
        flow.append(
            Paragraph("Potentially sensitive disallowed paths:", _styles["Warn"])
        )
        for p in d["sensitive_paths"]:
            flow.append(_ptext(f"- {p}", "Small"))
    else:
        flow.append(Spacer(1, 6))
        flow.append(Paragraph("No obviously sensitive paths found.", _styles["Ok"]))
    return flow


def _render_sitemap(r: CheckResult) -> list:
    if r.failed:
        return [_ptext(f"sitemap.xml check failed: {r.error}", "Bad")]
    d = r.data
    if not d:
        return _empty("No sitemap.xml data available.")
    if not d.get("found"):
        return _empty("No sitemap.xml could be found.")

    data = [["URL", "Status", "Type", "Entries"]]
    for s in d.get("sources", []):
        status = 200 if s.get("found") else s.get("status_code")
        data.append(
            [
                _p(s["url"]),
                _p(status),
                _p(s.get("type", "-")),
                _p(s.get("entry_count", "-")),
            ]
        )
    table = Table(
        data, repeatRows=1, colWidths=[3 * inch, 0.8 * inch, 0.8 * inch, 0.8 * inch]
    )
    table.setStyle(TABLE_STYLE)

    flow = [
        table,
        Spacer(1, 6),
        _ptext(f"Total unique URLs discovered: {d['total_urls']}", "Small"),
    ]
    sensitive = d.get("sensitive_urls", [])
    if sensitive:
        limit = 20
        flow.append(Spacer(1, 6))
        flow.append(Paragraph("Potentially sensitive URLs:", _styles["Warn"]))
        for u in sensitive[:limit]:
            flow.append(_ptext(f"- {u}", "Small"))
        if len(sensitive) > limit:
            flow.append(
                Paragraph(
                    f"+{len(sensitive) - limit} more matched, likely coincidental keyword matches.",
                    _styles["Dim"],
                )
            )
    else:
        flow.append(Spacer(1, 6))
        flow.append(Paragraph("No obviously sensitive URLs found.", _styles["Ok"]))
    return flow


def _render_csp(r: CheckResult) -> list:
    if r.failed:
        return [_ptext(f"CSP check failed: {r.error}", "Bad")]
    d = r.data
    if not d or not d.get("found"):
        return [Paragraph("No Content-Security-Policy header present.", _styles["Bad"])]

    flow = []
    if d.get("report_only"):
        flow.append(
            Paragraph(
                "Policy is enforced via Report-Only header (not blocking).",
                _styles["Warn"],
            )
        )
    flow.append(_ptext(d["raw"], "Mono"))
    flow.append(Spacer(1, 6))
    rows = [
        (k, " ".join(v) if v else "(empty)") for k, v in d.get("directives", {}).items()
    ]
    flow.append(_kv_table(rows))
    flow.append(Spacer(1, 6))
    flow += _issues_table(d.get("issues", []))
    return flow


def _render_cors(r: CheckResult) -> list:
    if r.failed:
        return [_ptext(f"CORS check failed: {r.error}", "Bad")]
    d = r.data
    if not d or not d.get("found"):
        return [
            Paragraph(
                "No CORS headers present - default same-origin policy applies.",
                _styles["Ok"],
            )
        ]

    flow = [_ptext(f"Test Origin used: {d['test_origin']}", "Dim"), Spacer(1, 4)]
    flow.append(
        _kv_table(
            [
                ("Access-Control-Allow-Origin", d.get("allow_origin")),
                ("Access-Control-Allow-Credentials", d.get("allow_credentials")),
                ("Access-Control-Allow-Methods", d.get("allow_methods")),
                ("Access-Control-Allow-Headers", d.get("allow_headers")),
            ]
        )
    )
    flow.append(Spacer(1, 6))
    flow += _issues_table(d.get("issues", []))
    return flow


def _render_hsts(r: CheckResult) -> list:
    if r.failed:
        return [_ptext(f"HSTS check failed: {r.error}", "Bad")]
    d = r.data
    if not d or not d.get("found"):
        return [
            Paragraph("No Strict-Transport-Security header present.", _styles["Bad"])
        ]

    flow = [_ptext(d["raw"], "Mono"), Spacer(1, 6)]
    flow.append(
        _kv_table(
            [
                ("max-age", d.get("max_age")),
                ("includeSubDomains", d.get("include_subdomains")),
                ("preload", d.get("preload")),
            ]
        )
    )
    flow.append(Spacer(1, 6))
    flow += _issues_table(d.get("issues", []))
    return flow


def _render_clickjacking(r: CheckResult) -> list:
    if r.failed:
        return [_ptext(f"Clickjacking check failed: {r.error}", "Bad")]
    d = r.data
    if not d:
        return _empty("No clickjacking data available.")

    flow = [
        _kv_table(
            [
                ("X-Frame-Options", d.get("x_frame_options")),
                ("CSP frame-ancestors", d.get("frame_ancestors")),
                ("Protected", d.get("protected")),
                ("Protection source", d.get("protection_source")),
            ]
        ),
        Spacer(1, 6),
    ]
    flow += _issues_table(d.get("issues", []))
    return flow


def _render_directory_listing(r: CheckResult) -> list:
    if r.failed:
        return [_ptext(f"Directory listing check failed: {r.error}", "Bad")]
    d = r.data
    if not d or not d.get("found"):
        return [
            Paragraph(
                "No open directory listings found on common paths.", _styles["Ok"]
            )
        ]

    flow = [_ptext(f"- {p}", "Small") for p in d["listings"]]
    flow.append(Spacer(1, 6))
    flow.append(
        Paragraph("These directories return a browsable file listing.", _styles["Warn"])
    )
    return flow


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
    return CheckResult(name=step, status=CheckStatus.ERROR, error="step did not run")


def _findings_table(findings: list[dict[str, str]]) -> list:
    if not findings:
        return [Paragraph("No issues found.", _styles["Ok"])]
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    ordered = sorted(findings, key=lambda f: order.get(f["severity"], 3))
    data = [["Severity", "Finding", "Recommendation"]]
    for f in ordered:
        data.append([_p(f["severity"]), _p(f["title"]), _p(f["recommendation"])])
    table = Table(data, repeatRows=1, colWidths=[0.8 * inch, 2 * inch, 3.2 * inch])
    table.setStyle(TABLE_STYLE)
    return [table]


def generate_pdf_report(
    target: str,
    results: dict[str, CheckResult],
    analysis: dict[str, Any],
    score: dict[str, Any],
    steps: list[str],
    output_path: Path,
) -> Path:
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=LETTER,
        topMargin=0.6 * inch,
        bottomMargin=0.6 * inch,
        leftMargin=0.6 * inch,
        rightMargin=0.6 * inch,
    )

    story = []
    story.append(Paragraph("4EYEZ Web Security Report", _styles["Title"]))
    safe_target = _break_long_tokens(xml_escape(target))
    story.append(
        Paragraph(
            f"Target: <b>{safe_target}</b> &nbsp;|&nbsp; "
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            _styles["Small"],
        )
    )
    story.append(Spacer(1, 12))

    grade_color = GRADE_COLORS.get(score["grade"], "#000000")
    summary_data = [
        [
            Paragraph(
                f"<font size=20 color='{grade_color}'>{score['score']}/100 ({score['grade']})</font>",
                _styles["Normal"],
            ),
            Paragraph(
                f"Overall Risk: <b>{xml_escape(score['risk'])}</b><br/>"
                f"High: {score['high']} &nbsp; Medium: {score['medium']} &nbsp; Low: {score['low']}",
                _styles["Small"],
            ),
        ]
    ]
    summary_table = Table(summary_data, colWidths=[2 * inch, 4 * inch])
    summary_table.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.5, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f5f5f5")),
            ]
        )
    )
    story.append(summary_table)
    story.append(Spacer(1, 12))

    exec_summary = generate_executive_summary(target, analysis, score)
    story.append(Paragraph("Executive Summary", _styles["SectionHeading"]))
    story.append(_ptext(exec_summary["narrative"], "Small"))
    if exec_summary["top_findings"]:
        story.append(Spacer(1, 6))
        story.append(Paragraph("Top findings:", _styles["Small"]))
        for f in exec_summary["top_findings"]:
            story.append(_ptext(f"- [{f['severity']}] {f['title']}", "Small"))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Risk Analysis", _styles["SectionHeading"]))
    story += _findings_table(analysis["findings"])

    for step in steps:
        result = results.get(step, _default_result(step))
        renderer = SECTION_RENDERERS.get(step)
        title = STEP_TITLES.get(step, step)
        story.append(_ptext(title, "SectionHeading"))
        story += (
            renderer(result)
            if renderer
            else _empty("No renderer available for this check.")
        )

    story.append(Spacer(1, 20))
    story.append(
        Paragraph(
            "Generated by 4EYEZ Web Security Scanner. For authorized security testing only.",
            _styles["Dim"],
        )
    )

    doc.build(story)
    return output_path


def save_pdf_report(
    target: str,
    results: dict[str, CheckResult],
    analysis: dict[str, Any],
    score: dict[str, Any],
    steps: list[str],
) -> Path:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    path = REPORT_DIR / safe_report_filename(target, "pdf")
    return generate_pdf_report(target, results, analysis, score, steps, path)

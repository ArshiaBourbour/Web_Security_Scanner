from rich.console import Console
from rich.table import Table

from core.result import CheckResult, CheckStatus


console = Console()

# Fixed order the report always follows.
STEPS = [
    "ssl",
    "headers",
    "dns",
    "whois",
    "html",
    "technology",
    "cookies",
    "http_methods",
    "robots",
    "sitemap",
    "csp",
]


def print_technology(result: CheckResult) -> None:
    console.rule("[bold cyan]Technology Detection[/bold cyan]")

    if result.failed:
        console.print(f"[red]Technology detection failed: {result.error}[/red]")
        return

    data = result.data

    if not data:
        console.print("[dim]No technologies detected.[/dim]")
        return

    table = Table(show_header=True)

    table.add_column("Category", style="cyan")
    table.add_column("Detected", style="green")

    technologies = data.get("technologies", data)

    for category, values in technologies.items():

        if not values:
            continue

        table.add_row(
            category.title(),
            ", ".join(values),
        )

    console.print(table)


def print_cookies(result: CheckResult) -> None:
    console.rule("[bold cyan]Cookie Security Analysis[/bold cyan]")

    if result.failed:
        console.print(f"[red]Cookie check failed: {result.error}[/red]")
        return

    data = result.data

    if not data:
        console.print("[dim]No cookies were set by the target.[/dim]")
        return

    table = Table(show_header=True)

    table.add_column("Name", style="cyan")
    table.add_column("Secure", style="green")
    table.add_column("HttpOnly", style="green")
    table.add_column("SameSite", style="green")
    table.add_column("Domain")
    table.add_column("Type")

    def _flag(value: bool) -> str:
        return "[green]yes[/green]" if value else "[red]no[/red]"

    for cookie in data.get("cookies", []):
        table.add_row(
            cookie["name"],
            _flag(cookie["secure"]),
            _flag(cookie["http_only"]),
            cookie["samesite"] if cookie["samesite"] else "[red]none[/red]",
            cookie["domain"] or "[dim]-[/dim]",
            "Session" if cookie["session_cookie"] else "Persistent",
        )

    console.print(table)
    console.print(
        f"[bold]Total:[/bold] {data['total']}  "
        f"[bold]Insecure:[/bold] {data['insecure_count']}  "
        f"[bold]Missing HttpOnly:[/bold] {data['no_httponly_count']}  "
        f"[bold]Missing SameSite:[/bold] {data['no_samesite_count']}"
    )


def print_http_methods(result: CheckResult) -> None:
    console.rule("[bold cyan]HTTP Methods Scan[/bold cyan]")

    if result.failed:
        console.print(f"[red]HTTP methods check failed: {result.error}[/red]")
        return

    data = result.data

    if not data:
        console.print("[dim]No HTTP methods could be determined.[/dim]")
        return

    table = Table(show_header=True)

    table.add_column("Method", style="cyan")
    table.add_column("Status Code")
    table.add_column("Result")

    labels = {
        "allowed": "[green]allowed[/green]",
        "disallowed": "[dim]not allowed[/dim]",
        "unknown": "[yellow]unclear[/yellow]",
        "unreachable": "[dim]no response[/dim]",
    }

    for entry in data.get("results", []):
        status = entry["status"]
        table.add_row(
            entry["method"],
            str(status) if status is not None else "[dim]-[/dim]",
            labels.get(entry["classification"], entry["classification"]),
        )

    console.print(table)

    if data.get("trace_enabled"):
        if data.get("trace_reflects_body"):
            console.print(
                "[red]TRACE is enabled and reflects request data in the response "
                "body (possible Cross-Site Tracing / XST risk).[/red]"
            )
        else:
            console.print("[yellow]TRACE method is enabled on this server.[/yellow]")

    if data.get("risky_methods"):
        console.print(
            f"[bold]Confirmed risky methods:[/bold] {', '.join(data['risky_methods'])}"
        )
    else:
        console.print("[green]No risky HTTP methods were confirmed as enabled.[/green]")

    console.print(
        "[dim]Note: 'unclear' means the route responded without confirming or "
        "denying that method (e.g. 404/403) — this is not a confirmed finding.[/dim]"
    )


def print_robots(result: CheckResult) -> None:
    console.rule("[bold cyan]robots.txt Scan[/bold cyan]")

    if result.failed:
        console.print(f"[red]robots.txt check failed: {result.error}[/red]")
        return

    data = result.data

    if not data:
        console.print("[dim]No robots.txt data available.[/dim]")
        return

    if not data.get("found"):
        status = data.get("status_code")
        console.print(
            f"[dim]No robots.txt found (status: {status}).[/dim]"
        )
        return

    console.print(
        f"[bold]User-agents referenced:[/bold] "
        f"{', '.join(data['user_agents']) if data['user_agents'] else '[dim]none[/dim]'}"
    )
    console.print(f"[bold]Disallowed paths:[/bold] {len(data['disallowed_paths'])}")
    console.print(f"[bold]Allowed paths:[/bold] {len(data['allowed_paths'])}")

    if data.get("crawl_delay"):
        console.print(f"[bold]Crawl-delay:[/bold] {data['crawl_delay']}")

    if data.get("sitemaps"):
        console.print("[bold]Sitemaps:[/bold]")
        for sitemap in data["sitemaps"]:
            console.print(f"  - {sitemap}")

    if data.get("sensitive_paths"):
        table = Table(show_header=True, title="Potentially Sensitive Disallowed Paths")
        table.add_column("Path", style="red")

        for path in data["sensitive_paths"]:
            table.add_row(path)

        console.print(table)
        console.print(
            "[yellow]These paths are publicly listed in robots.txt and may hint "
            "at sensitive areas of the site. robots.txt is not access control — "
            "anyone can read it.[/yellow]"
        )
    else:
        console.print(
            "[green]No obviously sensitive paths found in robots.txt.[/green]"
        )


def print_sitemap(result: CheckResult) -> None:
    console.rule("[bold cyan]sitemap.xml Scan[/bold cyan]")

    if result.failed:
        console.print(f"[red]sitemap.xml check failed: {result.error}[/red]")
        return

    data = result.data

    if not data:
        console.print("[dim]No sitemap.xml data available.[/dim]")
        return

    if not data.get("found"):
        console.print("[dim]No sitemap.xml could be found.[/dim]")
        return

    table = Table(show_header=True, title="Sitemap Sources")
    table.add_column("URL", style="cyan", overflow="fold")
    table.add_column("Status")
    table.add_column("Type")
    table.add_column("Entries")

    for source in data.get("sources", []):
        if source.get("found"):
            status_str = "[green]200[/green]"
            entry_type = source.get("type", "-")
            entry_count = str(source.get("entry_count", "-"))
            if source.get("error"):
                entry_type = f"[red]{source['error']}[/red]"
                entry_count = "-"
        else:
            status = source.get("status_code")
            status_str = f"[dim]{status if status is not None else 'no response'}[/dim]"
            entry_type = "-"
            entry_count = "-"

        table.add_row(source["url"], status_str, entry_type, entry_count)

    console.print(table)
    console.print(f"[bold]Total unique URLs discovered:[/bold] {data['total_urls']}")

    if data.get("truncated"):
        console.print(
            f"[dim](showing first {len(data['sample_urls'])} URLs)[/dim]"
        )

    if data.get("sensitive_urls"):
        sensitive_urls = data["sensitive_urls"]
        display_limit = 20

        sens_table = Table(show_header=True, title="Potentially Sensitive URLs")
        sens_table.add_column("URL", style="red", overflow="fold")

        for url in sensitive_urls[:display_limit]:
            sens_table.add_row(url)

        console.print(sens_table)

        if len(sensitive_urls) > display_limit:
            console.print(
                f"[dim](+{len(sensitive_urls) - display_limit} more matched "
                "keyword-based patterns, not shown)[/dim]"
            )

        if len(sensitive_urls) > display_limit:
            console.print(
                "[yellow]Note: a large number of matches usually means these are "
                "keyword coincidences in normal content (e.g. package/product "
                "names containing 'test' or 'admin'), not real sensitive paths. "
                "Review manually rather than treating this as a confirmed "
                "finding.[/yellow]"
            )
        else:
            console.print(
                "[yellow]These URLs are publicly listed in the sitemap and may "
                "hint at sensitive areas of the site.[/yellow]"
            )
    else:
        console.print("[green]No obviously sensitive URLs found in the sitemap.[/green]")


def print_csp(result: CheckResult) -> None:
    console.rule("[bold cyan]CSP Analysis[/bold cyan]")

    if result.failed:
        console.print(f"[red]CSP check failed: {result.error}[/red]")
        return

    data = result.data

    if not data or not data.get("found"):
        console.print("[red]No Content-Security-Policy header present.[/red]")
        return

    if data.get("report_only"):
        console.print("[yellow]Policy is enforced via Report-Only header (not blocking).[/yellow]")

    console.print(f"[dim]{data['raw']}[/dim]")

    table = Table(show_header=True)
    table.add_column("Directive", style="cyan")
    table.add_column("Values")

    for directive, values in data.get("directives", {}).items():
        table.add_row(directive, " ".join(values) if values else "[dim](empty)[/dim]")

    console.print(table)

    issues = data.get("issues", [])

    if not issues:
        console.print("[green]No common CSP misconfigurations detected.[/green]")
        return

    issues_table = Table(show_header=True, title="CSP Issues")
    issues_table.add_column("Severity")
    issues_table.add_column("Issue", style="cyan")
    issues_table.add_column("Detail")

    for issue in issues:
        issues_table.add_row(issue["severity"], issue["title"], issue["detail"])

    console.print(issues_table)


def _kv_table(rows: list[tuple[str, object]]) -> Table:
    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column(style="bold")
    table.add_column()
    for key, value in rows:
        table.add_row(key, str(value) if value not in (None, "") else "[dim]-[/dim]")
    return table


def print_ssl(result: CheckResult) -> None:
    console.rule("[bold cyan]SSL Information[/bold cyan]")
    if result.failed:
        console.print(f"[red]SSL check failed: {result.error}[/red]")
        return
    data = result.data
    if not data:
        console.print("[dim]No SSL data available.[/dim]")
        return
    console.print(
        _kv_table(
            [
                ("Subject", data.get("subject")),
                ("Issuer", data.get("issuer")),
                ("Valid From", data.get("notBefore")),
                ("Valid Until", data.get("notAfter")),
                ("Version", data.get("version")),
                ("Serial Number", data.get("serialNumber")),
                ("SAN", data.get("san")),
            ]
        )
    )


def print_headers(result: CheckResult) -> None:
    console.rule("[bold cyan]HTTP Security Headers[/bold cyan]")
    if result.failed:
        console.print(f"[red]Header check failed: {result.error}[/red]")
        return
    data = result.data
    if not data:
        console.print("[dim]No header data available.[/dim]")
        return
    security_headers = data.get("security_headers", {})
    rows = [("Server", data.get("server"))]
    rows += list(security_headers.items())
    console.print(_kv_table(rows))


def print_dns(result: CheckResult) -> None:
    console.rule("[bold cyan]DNS Records[/bold cyan]")
    if result.failed:
        console.print(f"[red]DNS check failed: {result.error}[/red]")
        return
    data = result.data
    if not data:
        console.print("[dim]No DNS data available.[/dim]")
        return
    for record_type in ("A", "AAAA", "MX", "NS", "TXT"):
        values = data.get(record_type) or []
        value_str = ", ".join(values) if values else "[dim]none found[/dim]"
        console.print(f"[bold]{record_type:<6}[/bold] {value_str}")


def print_whois(result: CheckResult) -> None:
    console.rule("[bold cyan]WHOIS Information[/bold cyan]")
    if result.failed:
        console.print(f"[red]WHOIS check failed: {result.error}[/red]")
        return
    data = result.data
    if not data:
        console.print("[dim]No WHOIS data available.[/dim]")
        return
    console.print(
        _kv_table(
            [
                ("Registrar", data.get("registrar")),
                ("Creation Date", data.get("creation_date")),
                ("Expiration Date", data.get("expiration_date")),
                ("Name Servers", data.get("name_servers")),
            ]
        )
    )


def print_html(result: CheckResult) -> None:
    console.rule("[bold cyan]HTML Analysis[/bold cyan]")
    if result.failed:
        console.print(f"[red]HTML check failed: {result.error}[/red]")
        return
    data = result.data
    if not data:
        console.print("[dim]No HTML data available.[/dim]")
        return
    console.print(
        _kv_table(
            [
                ("Script Tags", data.get("script_count")),
                ("Iframe Tags", data.get("iframe_count")),
                ("Form Tags", data.get("form_count")),
                ("External Links", data.get("external_links")),
            ]
        )
    )


PRINTERS = {
    "ssl": print_ssl,
    "headers": print_headers,
    "dns": print_dns,
    "whois": print_whois,
    "html": print_html,
    "technology": print_technology,
    "cookies": print_cookies,
    "http_methods": print_http_methods,
    "robots": print_robots,
    "sitemap": print_sitemap,
    "csp": print_csp,
}


def print_scan_results(results: dict, steps: list[str] = STEPS) -> None:
    for step in steps:
        default = CheckResult(
            name=step, status=CheckStatus.ERROR, error="step did not run"
        )
        PRINTERS[step](results.get(step, default))


def print_risk_analysis(analysis: dict) -> None:
    console.rule("[bold cyan]Risk Analysis[/bold cyan]")
    console.print(f"Overall Risk: [bold]{analysis['risk']}[/bold]")
    if not analysis["findings"]:
        console.print("[green]No issues found.[/green]")
        return
    for finding in analysis["findings"]:
        console.print(
            f"[{finding['severity']}] {finding['title']} "
            f"[dim]- {finding['recommendation']}[/dim]"
        )


def print_score(score: dict) -> None:
    console.rule("[bold cyan]Security Score[/bold cyan]")
    console.print(f"Score: {score['score']}/100  (Grade: {score['grade']})")
    console.print(f"Risk: {score['risk']}")
    console.print(
        f"High: {score['high']}  Medium: {score['medium']}  Low: {score['low']}"
    )
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
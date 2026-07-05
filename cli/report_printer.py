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
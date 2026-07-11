from rich.console import Console

from cli.banner import banner
from cli.progress_view import run_scan
from cli.report_printer import (
    STEPS,
    print_risk_analysis,
    print_scan_results,
    print_score,
)
from reporting.html_report import save_html_report
from reporting.json_report import save_json_report
from reporting.pdf_report import save_pdf_report
from scanners.analysis import RiskAnalyzer
from scanners.manager import ScanManager
from scanners.score_engine import ScoreEngine

console = Console()


def main() -> None:
    banner()

    target = input("Enter URL: ")

    manager = ScanManager(target)

    console.print("\n[bold]Scanning...[/bold]\n")
    results = run_scan(manager, STEPS)

    analysis = RiskAnalyzer(results).analyze()
    score = ScoreEngine(analysis).calculate()

    console.print()
    print_scan_results(results, STEPS)
    print_risk_analysis(analysis)
    print_score(score)

    report_path = save_html_report(target, results, analysis, score, STEPS)
    console.print(f"\n[bold green]HTML report saved to:[/bold green] {report_path}")

    pdf_path = save_pdf_report(target, results, analysis, score, STEPS)
    console.print(f"[bold green]PDF report saved to:[/bold green] {pdf_path}")

    json_path = save_json_report(target, results, analysis, score, STEPS)
    console.print(f"[bold green]JSON report saved to:[/bold green] {json_path}")


if __name__ == "__main__":
    main()

from rich.console import Console

from cli.banner import banner
from cli.progress_view import run_scan
from cli.report_printer import STEPS, print_risk_analysis, print_scan_results, print_score
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


if __name__ == "__main__":
    main()

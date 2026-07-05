from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console
from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn

from core.result import CheckResult
from scanners.manager import ScanManager

console = Console()

STEP_LABELS = {
    "ssl": "SSL",
    "headers": "Headers",
    "dns": "DNS",
    "whois": "WHOIS",
    "html": "HTML",
    "technology": "Technology",
}


def run_scan(manager: ScanManager, steps: list[str]) -> dict[str, CheckResult]:
    results: dict[str, CheckResult] = {}

    with Progress(
        TextColumn("[bold cyan]{task.fields[label]:<10}[/bold cyan]"),
        BarColumn(bar_width=30),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        tasks = {
            step: progress.add_task("", total=None, label=STEP_LABELS[step])
            for step in steps
        }

        def worker(step: str):
            result = manager.run_step(step)
            progress.update(tasks[step], total=100, completed=100)
            return step, result

        with ThreadPoolExecutor(max_workers=len(steps)) as executor:
            futures = [executor.submit(worker, step) for step in steps]
            for future in as_completed(futures):
                step, result = future.result()
                results[step] = result

    return results
from rich.console import Console
from rich.panel import Panel

console = Console()


def banner() -> None:
    console.print(
        Panel.fit(
            "[bold cyan]4EYEZ[/bold cyan]\n"
            "Web Security Scanner\n"
            "[yellow]Demo Version[/yellow]",
            border_style="cyan",
        )
    )
.

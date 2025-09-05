# /report/output_cli.py
from rich.console import Console
from rich.table import Table
from rich.text import Text

def generate_cli_output(results: list):
    """
    Displays the scan results in a beautifully formatted, color-coded table in the terminal.
    Groups results by host IP address.
    """
    console = Console()

    if not results:
        console.print("[yellow]No open ports found.[/yellow]")
        return

    # Group results by host
    grouped_results = {}
    for result in results:
        host = result.get('host')
        if host not in grouped_results:
            grouped_results[host] = []
        grouped_results[host].append(result)

    for host, host_results in grouped_results.items():
        console.print(f"\n[bold yellow]Scan Results for {host}[/bold yellow]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Port", style="cyan", justify="right")
        table.add_column("Status", style="green")
        table.add_column("Banner", style="white")

        for res in host_results:
            port = res.get('port')
            status = res.get('status')
            banner = res.get('banner', '')

            # Truncate and add ellipsis to banner
            display_banner = Text(banner[:100], style="dim")
            if len(banner) > 100:
                display_banner.append("...", style="dim")

            table.add_row(
                str(port),
                f"[green]{status}[/green]" if status == 'open' else status,
                display_banner
            )
        console.print(table)


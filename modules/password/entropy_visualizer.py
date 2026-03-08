"""
Password Entropy Visualizer — real-time character distribution
histogram + crack-time estimates. No external deps beyond stdlib + rich.
"""

import math
import string
from collections import Counter
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn
from rich import box

console = Console()


class EntropyVisualizer:

    def calculate_entropy(self, password: str) -> dict:
        """Calculate Shannon entropy and charset pool size."""
        if not password:
            return {"entropy_bits": 0, "pool_size": 0, "shannon": 0.0}

        pool = 0
        has_lower = any(c in string.ascii_lowercase for c in password)
        has_upper = any(c in string.ascii_uppercase for c in password)
        has_digit = any(c in string.digits for c in password)
        has_symbol = any(c in string.punctuation for c in password)
        has_space = " " in password

        if has_lower: pool += 26
        if has_upper: pool += 26
        if has_digit: pool += 10
        if has_symbol: pool += 32
        if has_space: pool += 1

        pool = max(pool, 1)
        entropy_bits = len(password) * math.log2(pool)

        # Shannon entropy (actual randomness in this specific string)
        counts = Counter(password)
        total = len(password)
        shannon = -sum(
            (c / total) * math.log2(c / total)
            for c in counts.values() if c > 0
        )

        return {
            "entropy_bits": round(entropy_bits, 2),
            "pool_size": pool,
            "shannon": round(shannon, 4),
            "length": len(password),
            "charset": {
                "lowercase": has_lower,
                "uppercase": has_upper,
                "digits": has_digit,
                "symbols": has_symbol,
                "spaces": has_space,
            }
        }

    def estimate_crack_time(self, entropy_bits: float) -> dict:
        """Estimate crack time at various attack speeds."""
        # Combinations = 2^entropy
        combinations = 2 ** entropy_bits

        speeds = {
            "Online (throttled, 100/hr)": 100 / 3600,
            "Online (fast, 10k/sec)": 10_000,
            "Offline MD5 (10B/sec)": 10_000_000_000,
            "Offline bcrypt (10k/sec)": 10_000,
            "GPU cluster (100B/sec)": 100_000_000_000,
        }

        results = {}
        for scenario, guesses_per_sec in speeds.items():
            seconds = (combinations / 2) / guesses_per_sec  # avg = half the space
            results[scenario] = self._humanize_time(seconds)

        return results

    def _humanize_time(self, seconds: float) -> str:
        if seconds < 1:
            return "[green]Instant[/green]"
        elif seconds < 60:
            return f"[red]{seconds:.1f} seconds[/red]"
        elif seconds < 3600:
            return f"[red]{seconds/60:.1f} minutes[/red]"
        elif seconds < 86400:
            return f"[yellow]{seconds/3600:.1f} hours[/yellow]"
        elif seconds < 31_536_000:
            return f"[yellow]{seconds/86400:.1f} days[/yellow]"
        elif seconds < 3.154e9:
            return f"[cyan]{seconds/31_536_000:.1f} years[/cyan]"
        else:
            return f"[green]{seconds/3.154e9:.2e} centuries[/green]"

    def char_distribution_chart(self, password: str) -> None:
        """Render a character frequency histogram."""
        if not password:
            return

        counts = Counter(password)
        total = len(password)
        max_count = max(counts.values())

        console.print("\n[bold cyan]── Character Distribution ──────────────[/bold cyan]")

        # Group by category
        categories = {
            "Lowercase": string.ascii_lowercase,
            "Uppercase": string.ascii_uppercase,
            "Digits": string.digits,
            "Symbols": string.punctuation + " ",
        }

        for cat_name, cat_chars in categories.items():
            present = {c: counts[c] for c in password if c in cat_chars}
            if not present:
                continue
            console.print(f"\n[dim]{cat_name}:[/dim]")
            for char, count in sorted(present.items(), key=lambda x: -x[1]):
                bar_len = int((count / max_count) * 30)
                bar = "█" * bar_len
                pct = count / total * 100
                console.print(f"  [yellow]{repr(char):4}[/yellow] {bar:<30} {count}× ({pct:.1f}%)")

    def display(self, password: str) -> None:
        """Full entropy analysis display."""
        stats = self.calculate_entropy(password)
        crack_times = self.estimate_crack_time(stats["entropy_bits"])

        # Entropy meter
        bits = stats["entropy_bits"]
        if bits < 28:
            strength = "[red]Terrible[/red]"
            meter_color = "red"
        elif bits < 36:
            strength = "[red]Weak[/red]"
            meter_color = "red"
        elif bits < 60:
            strength = "[yellow]Fair[/yellow]"
            meter_color = "yellow"
        elif bits < 80:
            strength = "[cyan]Strong[/cyan]"
            meter_color = "cyan"
        else:
            strength = "[green]Very Strong[/green]"
            meter_color = "green"

        meter_fill = min(int(bits / 128 * 40), 40)
        meter = f"[{meter_color}]{'█' * meter_fill}[/{meter_color}]{'░' * (40 - meter_fill)}"

        console.print(Panel(
            f"[bold]Entropy:[/bold] {bits} bits   [bold]Strength:[/bold] {strength}\n"
            f"[bold]Pool size:[/bold] {stats['pool_size']} chars   "
            f"[bold]Length:[/bold] {stats['length']}   "
            f"[bold]Shannon entropy:[/bold] {stats['shannon']} bits/char\n\n"
            f"{meter}",
            title="[bold cyan]🔐 Entropy Analysis[/bold cyan]",
            border_style="cyan"
        ))

        # Charset used
        console.print("\n[bold]Character sets used:[/bold]")
        for charset, used in stats["charset"].items():
            icon = "✅" if used else "❌"
            console.print(f"  {icon} {charset.capitalize()}")

        # Crack time table
        console.print("\n[bold cyan]── Estimated Crack Times ───────────────[/bold cyan]")
        table = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE)
        table.add_column("Attack Scenario", style="cyan", width=35)
        table.add_column("Time to Crack (avg)", style="yellow")

        for scenario, time_str in crack_times.items():
            table.add_row(scenario, time_str)
        console.print(table)

        # Character distribution
        self.char_distribution_chart(password)
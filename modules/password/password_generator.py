"""
Smart Password Generator — generates strong passwords and passphrases
with configurable policies, entropy display, and copy-ready output.
"""

import os
import math
import string
import secrets
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()

WORDLIST = [
    "anchor", "blizzard", "cipher", "dragon", "eclipse", "falcon",
    "glacier", "harbor", "ignite", "jungle", "kernel", "lantern",
    "magnet", "nebula", "oracle", "phantom", "quartz", "raven",
    "serpent", "thunder", "umbra", "vortex", "walrus", "xenon",
    "yearning", "zenith", "abacus", "beacon", "cobalt", "dagger",
    "ember", "fossil", "goblin", "herald", "inferno", "jester",
    "kraken", "lancer", "marble", "nimbus", "onyx", "pulsar",
    "quiver", "reflex", "summit", "tundra", "ulster", "vector",
    "warden", "xylem", "yonder", "zephyr", "abyss", "bastion",
    "crimson", "desert", "exodus", "ferret", "gravel", "haven",
    "island", "jackal", "kestrel", "limpet", "mirage", "nether",
    "origin", "piston", "quasar", "rampart", "saddle", "talon",
    "upland", "velvet", "wraith", "yttrium", "zircon", "alpine",
    "bronze", "canyon", "dagger", "errant", "fathom", "grotto",
]


class PasswordGenerator:

    def generate_random(
        self,
        length: int = 16,
        use_upper: bool = True,
        use_digits: bool = True,
        use_symbols: bool = True,
        exclude_ambiguous: bool = True,
    ) -> str:
        """Generate a cryptographically secure random password."""
        chars = string.ascii_lowercase
        required = []

        if use_upper:
            pool = string.ascii_uppercase
            if exclude_ambiguous:
                pool = pool.replace("I", "").replace("O", "")
            chars += pool
            required.append(secrets.choice(pool))

        if use_digits:
            pool = string.digits
            if exclude_ambiguous:
                pool = pool.replace("0", "").replace("1", "")
            chars += pool
            required.append(secrets.choice(pool))

        if use_symbols:
            pool = "!@#$%^&*-_=+?"
            chars += pool
            required.append(secrets.choice(pool))

        if exclude_ambiguous:
            chars = chars.replace("l", "").replace("I", "").replace("O", "").replace("0", "")

        # Fill the rest
        while len(required) < length:
            required.append(secrets.choice(chars))

        # Shuffle to avoid predictable positions
        password_list = list(required)
        for i in range(len(password_list) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            password_list[i], password_list[j] = password_list[j], password_list[i]

        return "".join(password_list)

    def generate_passphrase(
        self,
        word_count: int = 4,
        separator: str = "-",
        capitalize: bool = True,
        add_number: bool = True,
    ) -> str:
        """Generate a Diceware-style passphrase."""
        words = [secrets.choice(WORDLIST) for _ in range(word_count)]
        if capitalize:
            words = [w.capitalize() for w in words]
        phrase = separator.join(words)
        if add_number:
            phrase += separator + str(secrets.randbelow(9999)).zfill(4)
        return phrase

    def generate_pin(self, length: int = 6) -> str:
        """Generate a secure numeric PIN."""
        return "".join(str(secrets.randbelow(10)) for _ in range(length))

    def calculate_entropy(self, password: str) -> float:
        pool = 0
        if any(c in string.ascii_lowercase for c in password): pool += 26
        if any(c in string.ascii_uppercase for c in password): pool += 26
        if any(c in string.digits for c in password): pool += 10
        if any(c in string.punctuation for c in password): pool += 32
        return round(len(password) * math.log2(max(pool, 2)), 1)

    def display_passwords(self, passwords: list[dict]) -> None:
        """Display generated passwords with entropy info."""
        table = Table(
            title="🔐 Generated Passwords",
            show_header=True,
            header_style="bold magenta",
            box=box.ROUNDED
        )
        table.add_column("Type", style="cyan", width=15)
        table.add_column("Password", style="bold green", width=45)
        table.add_column("Entropy", style="yellow", width=12)
        table.add_column("Strength", width=15)

        for item in passwords:
            entropy = self.calculate_entropy(item["password"])
            if entropy < 40:
                strength = "[red]Weak[/red]"
            elif entropy < 60:
                strength = "[yellow]Fair[/yellow]"
            elif entropy < 80:
                strength = "[cyan]Strong[/cyan]"
            else:
                strength = "[green]Very Strong[/green]"

            table.add_row(
                item["type"],
                item["password"],
                f"{entropy} bits",
                strength
            )

        console.print(table)
        console.print("[dim]All passwords generated using cryptographically secure randomness (secrets module)[/dim]")

    def run_interactive(self) -> None:
        """Interactive password generation menu."""
        gen = PasswordGenerator()

        console.print(Panel(
            "[bold]Choose generation mode:[/bold]\n\n"
            "  [cyan]1.[/cyan] Random password (configurable)\n"
            "  [cyan]2.[/cyan] Passphrase (memorable, high entropy)\n"
            "  [cyan]3.[/cyan] Generate all types at once\n"
            "  [cyan]4.[/cyan] Secure PIN",
            title="[bold cyan]🔐 Password Generator[/bold cyan]",
            border_style="cyan"
        ))

        from rich.prompt import Prompt, Confirm
        choice = Prompt.ask("[cyan]Choice[/cyan]", choices=["1", "2", "3", "4"])

        results = []

        if choice == "1":
            length = int(Prompt.ask("[cyan]Length[/cyan]", default="16"))
            symbols = Confirm.ask("Include symbols?", default=True)
            for _ in range(3):
                pwd = gen.generate_random(length=length, use_symbols=symbols)
                results.append({"type": "Random", "password": pwd})

        elif choice == "2":
            words = int(Prompt.ask("[cyan]Word count[/cyan]", default="4"))
            sep = Prompt.ask("[cyan]Separator[/cyan]", default="-")
            for _ in range(3):
                pwd = gen.generate_passphrase(word_count=words, separator=sep)
                results.append({"type": "Passphrase", "password": pwd})

        elif choice == "3":
            results = [
                {"type": "Random-16",    "password": gen.generate_random(16)},
                {"type": "Random-24",    "password": gen.generate_random(24)},
                {"type": "Passphrase-4", "password": gen.generate_passphrase(4)},
                {"type": "Passphrase-5", "password": gen.generate_passphrase(5)},
                {"type": "PIN-6",        "password": gen.generate_pin(6)},
                {"type": "PIN-8",        "password": gen.generate_pin(8)},
            ]

        elif choice == "4":
            length = int(Prompt.ask("[cyan]PIN length[/cyan]", default="6"))
            for _ in range(5):
                results.append({"type": f"PIN-{length}", "password": gen.generate_pin(length)})

        gen.display_passwords(results)
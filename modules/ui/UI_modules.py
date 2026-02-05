from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import track
from rich import print as rprint

console = Console()

# Example: Beautiful menu
def display_menu():
    table = Table(title="🔐 Cyber Swiss Knife", show_header=True, header_style="bold magenta")
    table.add_column("Option", style="cyan", width=12)
    table.add_column("Feature", style="green")
    table.add_column("Description", style="yellow")
    
    table.add_row("1", "RSA Encryption", "Encrypt/Decrypt with RSA")
    table.add_row("2", "AES Encryption", "Symmetric encryption")
    table.add_row("3", "Password Checker", "Check password strength")
    table.add_row("4", "Hash Generator", "Generate secure hashes")
    table.add_row("5", "NEW: Breach Check", "Check if password is compromised")
    
    console.print(table)

# Example: Progress bars
def encrypt_file(filepath):
    with console.status("[bold green]Encrypting file...") as status:
        # Your encryption logic here
        pass
    console.print("✅ [bold green]Encryption complete!")
    

    
    

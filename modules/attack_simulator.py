import time
import itertools
import string
from rich.progress import Progress, SpinnerColumn, TimeElapsedColumn
from rich.console import Console
from rich.table import Table

console = Console()

class AttackSimulator:
    """Simulate common password attacks for educational purposes"""
    
    def __init__(self):
        self.common_passwords = self._load_common_passwords()
    
    def _load_common_passwords(self):
        """Load top 10000 common passwords"""
        # Create sample_files/common-passwords.txt with top passwords
        # Source: https://github.com/danielmiessler/SecLists
        try:
            with open('sample_files/common-passwords.txt', 'r') as f:
                return [line.strip() for line in f.readlines()]
        except FileNotFoundError:
            return ["password", "123456", "qwerty", "abc123", "letmein"]
    
    def dictionary_attack(self, target_hash, hash_type='sha256'):
        """
        Simulate dictionary attack on hashed password
        Returns: (success: bool, password: str, attempts: int, time_taken: float)
        """
        console.print("[bold yellow]🎯 Starting Dictionary Attack...[/bold yellow]")
        
        start_time = time.time()
        attempts = 0
        
        with Progress(
            SpinnerColumn(),
            *Progress.get_default_columns(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Trying passwords...", total=len(self.common_passwords))
            
            for password in self.common_passwords:
                attempts += 1
                
                # Hash the password
                if hash_type == 'sha256':
                    import hashlib
                    hashed = hashlib.sha256(password.encode()).hexdigest()
                elif hash_type == 'md5':
                    import hashlib
                    hashed = hashlib.md5(password.encode()).hexdigest()
                
                if hashed == target_hash:
                    end_time = time.time()
                    progress.stop()
                    return True, password, attempts, end_time - start_time
                
                progress.advance(task)
        
        end_time = time.time()
        return False, None, attempts, end_time - start_time
    
    def brute_force_attack(self, target_password, max_length=4, charset='lowercase'):
        """
        Simulate brute force attack (DEMONSTRATION ONLY - limited to short passwords)
        WARNING: Only use for educational purposes with short passwords
        """
        console.print("[bold red]⚠️  Brute Force Attack Simulator (Educational Only)[/bold red]")
        console.print(f"[dim]Testing passwords up to {max_length} characters...[/dim]\n")
        
        # Define character sets
        charsets = {
            'lowercase': string.ascii_lowercase,
            'uppercase': string.ascii_uppercase,
            'digits': string.digits,
            'mixed': string.ascii_letters + string.digits,
            'all': string.ascii_letters + string.digits + string.punctuation
        }
        
        chars = charsets.get(charset, string.ascii_lowercase)
        start_time = time.time()
        attempts = 0
        
        # Try all combinations from length 1 to max_length
        for length in range(1, max_length + 1):
            total = len(chars) ** length
            console.print(f"[cyan]Trying {total:,} combinations of length {length}...[/cyan]")
            
            with Progress(console=console) as progress:
                task = progress.add_task(f"[green]Length {length}", total=total)
                
                for guess in itertools.product(chars, repeat=length):
                    attempts += 1
                    password_guess = ''.join(guess)
                    
                    if password_guess == target_password:
                        end_time = time.time()
                        return True, password_guess, attempts, end_time - start_time
                    
                    progress.advance(task)
        
        end_time = time.time()
        return False, None, attempts, end_time - start_time
    
    def display_attack_results(self, success, password, attempts, time_taken):
        """Display attack results in a beautiful table"""
        table = Table(title="Attack Results", show_header=True, header_style="bold magenta")
        table.add_column("Metric", style="cyan", width=20)
        table.add_column("Value", style="yellow")
        
        if success:
            table.add_row("Status", "✅ [green]Password Cracked![/green]")
            table.add_row("Password Found", f"[bold red]{password}[/bold red]")
        else:
            table.add_row("Status", "❌ [red]Attack Failed[/red]")
        
        table.add_row("Attempts", f"{attempts:,}")
        table.add_row("Time Taken", f"{time_taken:.2f} seconds")
        table.add_row("Speed", f"{attempts/time_taken:.0f} attempts/sec")
        
        console.print(table)
        
        # Educational message
        if success and time_taken < 1:
            console.print("\n[bold red]⚠️  SECURITY LESSON:[/bold red]")
            console.print("[yellow]This password was cracked in under 1 second![/yellow]")
            console.print("[yellow]Use longer passwords with mixed characters for better security.[/yellow]")

    def demonstrate_rainbow_table(self):
        """Demonstrate why salting is important"""
        console.print("[bold cyan]🌈 Rainbow Table Attack Demonstration[/bold cyan]\n")
        
        import hashlib
        
        # Common passwords
        passwords = ["password", "123456", "qwerty", "abc123"]
        
        # Create "rainbow table" (precomputed hashes)
        console.print("[yellow]Step 1: Building rainbow table (precomputed hashes)...[/yellow]")
        rainbow_table = {}
        for pwd in passwords:
            hash_val = hashlib.sha256(pwd.encode()).hexdigest()
            rainbow_table[hash_val] = pwd
        
        table = Table(title="Rainbow Table", show_header=True)
        table.add_column("Hash (SHA-256)", style="cyan")
        table.add_column("Original Password", style="red")
        
        for hash_val, pwd in rainbow_table.items():
            table.add_row(hash_val[:32] + "...", pwd)
        
        console.print(table)
        
        # Demonstrate cracking
        console.print("\n[yellow]Step 2: Instant lookup attack...[/yellow]")
        target = hashlib.sha256("password".encode()).hexdigest()
        
        if target in rainbow_table:
            console.print(f"[bold red]💥 Cracked instantly! Password: {rainbow_table[target]}[/bold red]")
        
        # Show defense
        console.print("\n[green]Defense: Add salt to make rainbow tables useless[/green]")
        import os
        salt = os.urandom(16).hex()
        salted_hash = hashlib.sha256((salt + "password").encode()).hexdigest()
        
        console.print(f"Salt: {salt}")
        console.print(f"Salted hash: {salted_hash[:32]}...")
        console.print("[green]✅ Same password, different hash! Rainbow table is useless.[/green]")

# Usage example
def run_attack_demo():
    simulator = AttackSimulator()
    
    console.print("[bold]Choose attack type:[/bold]")
    console.print("1. Dictionary Attack")
    console.print("2. Brute Force (short passwords only)")
    console.print("3. Rainbow Table Demo")
    
    choice = console.input("\n[cyan]Enter choice: [/cyan]")
    
    if choice == "1":
        # Dictionary attack demo
        import hashlib
        target = "password"  # Example weak password
        target_hash = hashlib.sha256(target.encode()).hexdigest()
        
        success, pwd, attempts, time_taken = simulator.dictionary_attack(target_hash)
        simulator.display_attack_results(success, pwd, attempts, time_taken)
    
    elif choice == "2":
        # Brute force demo
        target = "abc"  # Very short for demo
        success, pwd, attempts, time_taken = simulator.brute_force_attack(
            target, max_length=3, charset='lowercase'
        )
        simulator.display_attack_results(success, pwd, attempts, time_taken)
    
    elif choice == "3":
        simulator.demonstrate_rainbow_table()
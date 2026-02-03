import hashlib
import requests
from rich.console import Console
console = Console()

class BreachChecker:
    """Check if passwords have been compromised in known data breaches using HaveIbeenpwned API"""
    def __init__(self):
        self.api_url = "https://api.pwnedpasswords.com/range/"
        
    def check_password(self,password):
        """check password against HIBP database using k-anonymity 
        Returns : (is pwned: bool, count :int)"""
        
        # hash the password using SHA1
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        try :
            #query API with first 5 chars 
            response = requests.get(f"{self.api_url}{prefix}",timeout=5)
            response.raise_for_status()
            
            #check if suffix is in response
            hashes = (line.split(':') for line in response.text.splitlines())
            for hash_suffix,count in hashes:
                if hash_suffix == suffix:
                    return True, int(count)
            return False, 0
        except requests.RequestException as e:
            console.print(f"[red]Error querying HaveIbeenpwned API: {e}[/red]")
            return None, 0
    def display_result(self,password,is_pwned,count):
        """Display the result of the breach check"""
        if is_pwned is None:
            console.print("[yellow]⚠️  Could not verify password against breach database[/yellow]")
        elif is_pwned:
            console.print(f"[bold red]🚨 DANGER! Password found in {count:,} data breaches![/bold red]")
            console.print("[red]This password has been compromised. Choose a different one immediately.[/red]")
        else:
            console.print("[bold green]✅ Good news! Password not found in known breaches.[/bold green]")
            console.print("[dim]Note: This doesn't guarantee the password is strong.[/dim]")
            
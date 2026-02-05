"""
Cyber Swiss Knife v2.0
A comprehensive cybersecurity toolkit for encryption, security auditing, and penetration testing
"""

import sys
from pathlib import Path
from getpass import getpass

# Rich imports for beautiful UI
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich import print as rprint

# Import all your modules
# Note: Make sure these are in a 'modules' directory
try:
    from modules.hashing.hash import hash_file, verify_integrity
    from modules.encryption.encryption import aes_ed, rsa_ed
    from modules.password.passwords import check_strength, hash_pw, verify_password
    from modules.password.breach_checker import BreachChecker
    from modules.attack_tools.attack_simulator import AttackSimulator
    from modules.attack_tools.phishing_detector import PhishingDetector
    from modules.security_auditor.ssh_auditor import SSHKeyAuditor
    from modules.security_auditor.cert_checker import CertificateChecker
    from modules.security_auditor.git_scanner import GitSecretScanner
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Make sure all module files are in the 'modules' directory")
    sys.exit(1)

console = Console()


class CyberSwissKnife:
    """Main application class"""
    
    def __init__(self):
        self.running = True
        self.breach_checker = BreachChecker()
        self.attack_simulator = AttackSimulator()
        self.phishing_detector = PhishingDetector()
        self.ssh_auditor = SSHKeyAuditor()
        self.cert_checker = CertificateChecker()
        self.git_scanner = GitSecretScanner()
    
    def display_banner(self):
        """Display welcome banner"""
        banner = """
[bold cyan]╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║        🔐 CYBER SWISS KNIFE v2.0 🔐                          ║
║        The Ultimate Security Toolkit                          ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝[/bold cyan]

[yellow]Welcome, Security Professional![/yellow]

[dim]Your mission, should you choose to accept it:
  • Analyze and hash files to detect tampering
  • Encrypt and decrypt messages with RSA and AES
  • Securely manage passwords and assess their strength
  • Audit SSH keys and SSL certificates
  • Detect phishing attempts and scan for secrets
  • Simulate attacks for educational purposes[/dim]

[bold green]All systems online. Data protection protocols active.[/bold green]
[bold red]⚠️  Use responsibly and ethically! ⚠️[/bold red]
"""
        console.print(Panel(banner, border_style="cyan", padding=(1, 2)))
    
    def display_main_menu(self):
        """Display main menu with categories"""
        table = Table(
            title="🔐 Main Menu",
            show_header=True,
            header_style="bold magenta",
            border_style="cyan"
        )
        table.add_column("Option", style="cyan", width=8, justify="center")
        table.add_column("Category", style="green", width=20)
        table.add_column("Feature", style="yellow", width=35)
        
        # Cryptography Section
        table.add_row("1", "[bold]🔒 Cryptography[/bold]", "")
        table.add_row("  1.1", "  Hash File", "  SHA-256 file hashing")
        table.add_row("  1.2", "  Verify Integrity", "  Compare file hashes")
        table.add_row("  1.3", "  AES Encryption", "  Symmetric encryption/decryption")
        table.add_row("  1.4", "  RSA Encryption", "  Asymmetric encryption/decryption")
        
        # Password Security Section
        table.add_row("", "", "")
        table.add_row("2", "[bold]🔑 Password Security[/bold]", "")
        table.add_row("  2.1", "  Password Manager", "  Check, hash, and verify passwords")
        table.add_row("  2.2", "  Breach Checker", "  Check against HaveIBeenPwned")
        table.add_row("  2.3", "  Attack Simulator", "  Educational password cracking demo")
        
        # Security Auditing Section
        table.add_row("", "", "")
        table.add_row("3", "[bold]🛡️  Security Auditing[/bold]", "")
        table.add_row("  3.1", "  SSH Key Auditor", "  Scan and audit SSH keys")
        table.add_row("  3.2", "  Certificate Checker", "  Check SSL/TLS certificates")
        table.add_row("  3.3", "  Git Secret Scanner", "  Detect committed secrets")
        table.add_row("  3.4", "  Phishing Detector", "  Analyze emails for phishing")
        
        # Network tools 
        table.add_row("4","[bold]🌐 Network Tools[/bold]","")
        table.add_row("  4.1","  Port Scanner","   Scan for open ports on a Network ports")
        table.add_row("  4.2","   WhoisLookup","   Domain Information")
        table.add_row("  4.3","  IP Geolocation","  Locate IP address")        
        # System
        table.add_row("", "", "")
        table.add_row("0", "[bold red]Exit[/bold red]", "Exit the application")
        
        console.print(table)
    
    # ==================== Cryptography Features ====================
    
    def hash_file_menu(self):
        """Hash a file using SHA-256"""
        console.print("\n[bold cyan]📄 File Hashing[/bold cyan]")
        file_path = Prompt.ask("[cyan]Enter file path[/cyan]")
        
        try:
            with console.status("[bold green]Hashing file..."):
                file_hash = hash_file(file_path)
            
            console.print(Panel(
                f"[bold]File:[/bold] {file_path}\n"
                f"[bold]SHA-256:[/bold] [yellow]{file_hash}[/yellow]",
                title="✅ Hash Generated",
                border_style="green"
            ))
        except FileNotFoundError:
            console.print("[red]❌ File not found![/red]")
        except Exception as e:
            console.print(f"[red]❌ Error: {e}[/red]")
    
    def verify_integrity_menu(self):
        """Verify integrity between two files"""
        console.print("\n[bold cyan]🔍 File Integrity Verification[/bold cyan]")
        file1 = Prompt.ask("[cyan]Enter first file path[/cyan]")
        file2 = Prompt.ask("[cyan]Enter second file path[/cyan]")
        
        try:
            with console.status("[bold green]Comparing files..."):
                result = verify_integrity(file1, file2)
            
            if "intact" in result.lower():
                console.print(f"[green]✅ {result}[/green]")
            else:
                console.print(f"[red]⚠️  {result}[/red]")
        except FileNotFoundError:
            console.print("[red]❌ One or both files not found![/red]")
        except Exception as e:
            console.print(f"[red]❌ Error: {e}[/red]")
    
    def aes_encryption_menu(self):
        """AES encryption/decryption demo"""
        console.print("\n[bold cyan]🔐 AES Encryption (AES-256-GCM)[/bold cyan]")
        message = Prompt.ask("[cyan]Enter message to encrypt[/cyan]")
        
        try:
            with console.status("[bold green]Encrypting..."):
                key, ciphertext, plaintext = aes_ed(message)
            
            console.print(Panel(
                f"[bold]Original:[/bold] {message}\n\n"
                f"[bold]AES Key:[/bold]\n[yellow]{key}[/yellow]\n\n"
                f"[bold]Ciphertext:[/bold]\n[red]{ciphertext[:100]}...[/red]\n\n"
                f"[bold]Decrypted:[/bold] [green]{plaintext}[/green]",
                title="✅ AES Encryption Complete",
                border_style="green"
            ))
        except Exception as e:
            console.print(f"[red]❌ Error: {e}[/red]")
    
    def rsa_encryption_menu(self):
        """RSA encryption/decryption demo"""
        console.print("\n[bold cyan]🔑 RSA Encryption (2048-bit)[/bold cyan]")
        message = Prompt.ask("[cyan]Enter message to encrypt[/cyan]")
        
        try:
            with console.status("[bold green]Encrypting with RSA..."):
                ciphertext, plaintext = rsa_ed(message)
            
            console.print(Panel(
                f"[bold]Original:[/bold] {message}\n\n"
                f"[bold]Encrypted (hex):[/bold]\n[red]{ciphertext[:100]}...[/red]\n\n"
                f"[bold]Decrypted:[/bold] [green]{plaintext}[/green]",
                title="✅ RSA Encryption Complete",
                border_style="green"
            ))
        except Exception as e:
            console.print(f"[red]❌ Error: {e}[/red]")
    
    # ==================== Password Security Features ====================
    
    def password_manager_menu(self):
        """Complete password management workflow"""
        console.print("\n[bold cyan]🔑 Password Manager[/bold cyan]")
        
        # Check password strength
        while True:
            password = getpass("Enter a password to check strength: ")
            console.print("\n[bold]Strength Analysis:[/bold]")
            strength_result = check_strength(password)
            console.print(strength_result)
            
            if strength_result.startswith("Weak"):
                console.print("\n[yellow]⚠️  Please choose a stronger password.[/yellow]")
                if not Confirm.ask("Try another password?", default=True):
                    return
            else:
                break
        
        # Hash the password
        with console.status("[bold green]Hashing password..."):
            hashed = hash_pw(password)
        
        console.print(f"\n[bold]Hashed Password (bcrypt):[/bold]\n[yellow]{hashed.decode()}[/yellow]")
        
        # Verify password
        console.print("\n[bold cyan]Password Verification[/bold cyan]")
        attempt = getpass("Re-enter the password to verify: ")
        result = verify_password(attempt, hashed)
        
        if "granted" in result.lower():
            console.print(f"[green]✅ {result}[/green]")
        else:
            console.print(f"[red]❌ {result}[/red]")
    
    def breach_checker_menu(self):
        """Check if password has been breached"""
        console.print("\n[bold cyan]🔍 Password Breach Checker[/bold cyan]")
        console.print("[dim]Uses HaveIBeenPwned API (k-anonymity - your password is never sent)[/dim]\n")
        
        password = getpass("Enter password to check: ")
        
        with console.status("[bold yellow]Checking against breach database..."):
            is_pwned, count = self.breach_checker.check_password(password)
        
        self.breach_checker.display_result(password, is_pwned, count)
        
        # Also show strength
        console.print("\n[bold]Password Strength:[/bold]")
        strength_result = check_strength(password)
        console.print(strength_result)
    
    def attack_simulator_menu(self):
        """Educational attack simulation"""
        console.print("\n[bold red]⚔️  Attack Simulator (Educational Only)[/bold red]")
        console.print("[yellow]⚠️  For educational purposes only![/yellow]\n")
        
        attack_table = Table(show_header=True, header_style="bold magenta")
        attack_table.add_column("Option", style="cyan", width=8)
        attack_table.add_column("Attack Type", style="yellow")
        
        attack_table.add_row("1", "Dictionary Attack")
        attack_table.add_row("2", "Brute Force (short passwords)")
        attack_table.add_row("3", "Rainbow Table Demo")
        attack_table.add_row("0", "Back to main menu")
        
        console.print(attack_table)
        
        choice = Prompt.ask("\n[cyan]Choose attack type[/cyan]", choices=["1", "2", "3", "0"])
        
        if choice == "1":
            self.dictionary_attack_demo()
        elif choice == "2":
            self.brute_force_demo()
        elif choice == "3":
            self.attack_simulator.demonstrate_rainbow_table()
    
    def dictionary_attack_demo(self):
        """Run dictionary attack demo"""
        console.print("\n[bold yellow]📖 Dictionary Attack Demo[/bold yellow]")
        console.print("[dim]Testing against common passwords...[/dim]\n")
        
        import hashlib
        
        # Let user choose a password or use default
        use_custom = Confirm.ask("Use custom password for demo?", default=False)
        
        if use_custom:
            target = Prompt.ask("[cyan]Enter password to attack[/cyan]")
        else:
            target = "password123"
            console.print(f"[dim]Using default weak password: {target}[/dim]")
        
        target_hash = hashlib.sha256(target.encode()).hexdigest()
        
        success, pwd, attempts, time_taken = self.attack_simulator.dictionary_attack(target_hash)
        self.attack_simulator.display_attack_results(success, pwd, attempts, time_taken)
    
    def brute_force_demo(self):
        """Run brute force demo"""
        console.print("\n[bold yellow]💪 Brute Force Demo[/bold yellow]")
        console.print("[yellow]⚠️  Limited to very short passwords for demonstration[/yellow]\n")
        
        use_custom = Confirm.ask("Use custom password for demo?", default=False)
        
        if use_custom:
            target = Prompt.ask("[cyan]Enter short password (max 4 chars)[/cyan]")
            if len(target) > 4:
                console.print("[red]Password too long! Using first 4 characters.[/red]")
                target = target[:4]
        else:
            target = "abc"
            console.print(f"[dim]Using default: {target}[/dim]")
        
        # Choose charset
        console.print("\n[bold]Character set:[/bold]")
        console.print("1. Lowercase only (fastest)")
        console.print("2. Lowercase + uppercase")
        console.print("3. Alphanumeric")
        
        charset_choice = Prompt.ask("[cyan]Choose charset[/cyan]", choices=["1", "2", "3"], default="1")
        charset_map = {"1": "lowercase", "2": "mixed", "3": "mixed"}
        
        success, pwd, attempts, time_taken = self.attack_simulator.brute_force_attack(
            target, 
            max_length=len(target), 
            charset=charset_map[charset_choice]
        )
        self.attack_simulator.display_attack_results(success, pwd, attempts, time_taken)
    
    # ==================== Security Auditing Features ====================
    
    def ssh_auditor_menu(self):
        """Run SSH key security audit"""
        console.print("\n[bold cyan]🔑 SSH Key Security Audit[/bold cyan]")
        
        if not Confirm.ask("Scan your ~/.ssh directory?", default=True):
            return
        
        with console.status("[bold green]Scanning SSH keys..."):
            keys = self.ssh_auditor.scan_ssh_directory()
            auth_keys = self.ssh_auditor.check_authorized_keys()
        
        self.ssh_auditor.display_audit_results(keys, auth_keys)
    
    def cert_checker_menu(self):
        """Check SSL/TLS certificates"""
        console.print("\n[bold cyan]🔒 SSL/TLS Certificate Checker[/bold cyan]")
        console.print("[dim]Enter websites to check (press Enter on empty line to finish)[/dim]\n")
        
        urls = []
        while True:
            url = Prompt.ask("[cyan]Website URL[/cyan]", default="")
            if not url:
                break
            urls.append(url)
        
        if not urls:
            console.print("[yellow]No websites provided[/yellow]")
            return
        
        results = self.cert_checker.check_multiple_sites(urls)
        self.cert_checker.display_results(results)
    
    def git_scanner_menu(self):
        """Scan git repository for secrets"""
        console.print("\n[bold cyan]🔍 Git Secret Scanner[/bold cyan]")
        console.print("[yellow]⚠️  This will scan for API keys, passwords, and other secrets[/yellow]\n")
        
        directory = Prompt.ask(
            "[cyan]Enter directory to scan[/cyan]",
            default="."
        )
        
        findings = self.git_scanner.scan_directory(directory)
        self.git_scanner.display_findings(findings)
    
    def phishing_detector_menu(self):
        """Analyze email for phishing"""
        console.print("\n[bold cyan]📧 Phishing Email Analyzer[/bold cyan]")
        console.print("[dim]Analyze emails for common phishing indicators[/dim]\n")
        
        # Option to use sample or custom email
        use_sample = Confirm.ask("Use sample phishing email?", default=True)
        
        if use_sample:
            sender = "security@paypa1-verify.tk"
            subject = "URGENT: Verify your account within 24 hours"
            email_body = """
Dear PayPal Customer,

We have detected unusual activity on your account.
Please verify your identity immediately by clicking here:
http://192.168.1.1/paypal-verify.php?user=12345

Your account will be suspended if you don't act within 24 hours.

Thank you,
PayPal Security Team
            """
            console.print("[dim]Using sample phishing email...[/dim]\n")
        else:
            sender = Prompt.ask("[cyan]Sender email[/cyan]")
            subject = Prompt.ask("[cyan]Email subject[/cyan]")
            console.print("[cyan]Email body (press Ctrl+D or Ctrl+Z when done):[/cyan]")
            lines = []
            try:
                while True:
                    line = input()
                    lines.append(line)
            except EOFError:
                pass
            email_body = "\n".join(lines)
        
        with console.status("[bold yellow]Analyzing email..."):
            risk_score, indicators = self.phishing_detector.analyze_email(
                email_body, sender, subject
            )
        
        self.phishing_detector.display_analysis(risk_score, indicators, sender, subject)
    
    # ==================== Main Loop ====================
    
    def run(self):
        """Main application loop"""
        self.display_banner()
        
        while self.running:
            console.print()  # Spacing
            self.display_main_menu()
            
            choice = Prompt.ask(
                "\n[bold cyan]Enter your choice[/bold cyan]",
                default="0"
            )
            
            try:
                self.handle_choice(choice)
            except KeyboardInterrupt:
                console.print("\n[yellow]Operation cancelled[/yellow]")
            except Exception as e:
                console.print(f"\n[red]❌ Error: {e}[/red]")
                console.print("[dim]Please try again or report this issue[/dim]")
            
            if self.running and choice != "0":
                console.print("\n" + "="*70)
                Prompt.ask("[dim]Press Enter to continue[/dim]", default="")
    
    def handle_choice(self, choice):
        """Handle menu selection"""
        choice = choice.strip().lower()
        
        # Cryptography
        if choice == "1.1":
            self.hash_file_menu()
        elif choice == "1.2":
            self.verify_integrity_menu()
        elif choice == "1.3":
            self.aes_encryption_menu()
        elif choice == "1.4":
            self.rsa_encryption_menu()
        
        # Password Security
        elif choice == "2.1":
            self.password_manager_menu()
        elif choice == "2.2":
            self.breach_checker_menu()
        elif choice == "2.3":
            self.attack_simulator_menu()
        
        # Security Auditing
        elif choice == "3.1":
            self.ssh_auditor_menu()
        elif choice == "3.2":
            self.cert_checker_menu()
        elif choice == "3.3":
            self.git_scanner_menu()
        elif choice == "3.4":
            self.phishing_detector_menu()
        elif choice == "4.1":
            from modules.network.port_scanner import run_port_scanner
            run_port_scanner()
        
        # Exit
        elif choice == "0":
            self.exit_application()
        
        else:
            console.print(f"[red]Invalid choice: {choice}[/red]")
            console.print("[yellow]Please enter a valid option (e.g., 1.1, 2.2, 3.3, or 0)[/yellow]")
    
    def exit_application(self):
        """Exit the application"""
        console.print("\n[bold cyan]" + "="*70 + "[/bold cyan]")
        console.print(Panel(
            "[bold yellow]Thank you for using Cyber Swiss Knife![/bold yellow]\n\n"
            "[green]Stay safe and secure! 🔐[/green]\n"
            "[dim]Remember: Use these tools responsibly and ethically.[/dim]",
            title="👋 Goodbye, Security Professional",
            border_style="cyan"
        ))
        self.running = False


def main():
    """Application entry point"""
    try:
        app = CyberSwissKnife()
        app.run()
    except KeyboardInterrupt:
        console.print("\n\n[yellow]Application interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Fatal error: {e}[/red]")
        console.print("[dim]Please check your installation and try again[/dim]")
        sys.exit(1)


if __name__ == "__main__":
    main()
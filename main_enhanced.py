"""
Cyber Swiss Knife v3.0
A comprehensive cybersecurity toolkit
"""

import sys
import time
from pathlib import Path
from getpass import getpass

# Rich imports
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich import print as rprint
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.layout import Layout
from rich.align import Align
from rich import box

# Import modules
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
    from modules.forensics.encoder_decoder import EncoderDecoder
    from modules.forensics.metadata_extractor import MetadataExtractor
    from modules.network.ip_geolocation import IPGeolocation
    from modules.network.whois_lookup import WhoisLookup
    from modules.password.password_policy import PasswordPolicy
    from modules.reporting.report_generator import ReportGenerator
    from modules.plugins.plugins_manager import PluginManager
    from modules.security_auditor.jwt_analyzer import JWTAnalyzer
    from modules.security_auditor.config_auditor import ConfigAuditor
    from modules.forensics.steg_detector import SteganographyDetector
    from modules.password.entropy_visualizer import EntropyVisualizer
    from modules.password.password_generator import PasswordGenerator
    
except ImportError as e:
    print(f"❌ Import Error: {e}")
    print("\n💡 Make sure all modules are in the correct directories!")
    sys.exit(1)

console = Console()

# ASCII Art

ASCII_BANNER = """[bold purple]
 ██████╗██╗  ██╗██╗███╗   ███╗███████╗██████╗  █████╗ 
██╔════╝██║  ██║██║████╗ ████║██╔════╝██╔══██╗██╔══██╗
██║     ███████║██║██╔████╔██║█████╗  ██████╔╝███████║
██║     ██╔══██║██║██║╚██╔╝██║██╔══╝  ██╔══██╗██╔══██║
╚██████╗██║  ██║██║██║ ╚═╝ ██║███████╗██║  ██║██║  ██║
 ╚═════╝╚═╝  ╚═╝╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
[/bold purple]"""

class CyberSwissKnife:
    def __init__(self):
        self.running = True
        self.breach_checker = BreachChecker()
        self.attack_simulator = AttackSimulator()
        self.phishing_detector = PhishingDetector()
        self.ssh_auditor = SSHKeyAuditor()
        self.cert_checker = CertificateChecker()
        self.git_scanner = GitSecretScanner()
        self.encoder_decoder = EncoderDecoder()
        self.metadata_extractor = MetadataExtractor()
        self.ip_geo = IPGeolocation()
        self.whois = WhoisLookup()
        self.password_policy = PasswordPolicy()
        self.report_generator = ReportGenerator()
        self.plugin_manager = PluginManager()
        self.jwt_analyzer = JWTAnalyzer()
        self.config_auditor = ConfigAuditor()
        self.steg_detector = SteganographyDetector()
        self.entropy_visualizer = EntropyVisualizer()
        self.password_generator = PasswordGenerator()
    
    def display_welcome_screen(self):
        """Show animated welcome screen"""
        console.clear()
        console.print(Align.center(ASCII_BANNER))
        
        welcome = Panel(
            Align.center(
                "[bold yellow]🔐 The Ultimate Cybersecurity Toolkit 🔐[/bold yellow]\n\n"
                "[cyan]Version:[/cyan] [green]v3.0[/green] | [cyan]Status:[/cyan] [green]● Online[/green]\n\n"
                "[dim]Encryption • Password Security • Network Analysis\nSecurity Auditing • Attack Simulation[/dim]"
            ),
            border_style="cyan",
            box=box.DOUBLE
        )
        console.print(welcome)
        
        notice = Panel(
            "[bold red]⚠️  SECURITY NOTICE ⚠️[/bold red]\n\n"
            "[yellow]Authorized Use Only:[/yellow]\n"
            "✓ Educational purposes\n✓ Authorized security testing\n✓ Personal security auditing\n\n"
            "[red]Prohibited:[/red]\n"
            "✗ Unauthorized access attempts\n✗ Attacking systems you don't own\n\n"
            "[bold]By using this tool, you agree to use it responsibly.[/bold]",
            border_style="red"
        )
        console.print(Align.center(notice))
        
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=True) as progress:
            task = progress.add_task("[cyan]Initializing...", total=100)
            for i in range(100):
                progress.update(task, advance=1)
                time.sleep(0.01)
        
        console.print("\n[green]✅ Ready[/green]")
        Prompt.ask("\n[dim]Press Enter[/dim]", default="")
    
    def display_main_menu(self):
        """Show main menu"""
        console.print("\n")
        console.print(Panel(Align.center("[bold cyan]CYBER SWISS KNIFE - CONTROL PANEL[/bold cyan]"), border_style="cyan", box=box.DOUBLE))
        
        table = Table(show_header=True, header_style="bold magenta on black", border_style="cyan", box=box.ROUNDED)
        table.add_column("CMD", style="bold cyan", justify="center", width=6)
        table.add_column("Module", style="bold green", width=22)
        table.add_column("Feature", style="yellow", width=40)
        table.add_column("✓", style="green", justify="center", width=4)
        
        table.add_row("", "[bold reverse cyan] 🔒 CRYPTOGRAPHY [/bold reverse cyan]", "", "")
        table.add_row("1.1", "  Hash File", "  SHA-256 file hashing", "✓")
        table.add_row("1.2", "  Verify Integrity", "  Compare file hashes", "✓")
        table.add_row("1.3", "  AES Encryption", "  AES-256-GCM", "✓")
        table.add_row("1.4", "  RSA Encryption", "  2048-bit RSA", "✓")
        
        table.add_row("", "", "", "")
        table.add_row("", "[bold reverse yellow] 🔑 PASSWORD SECURITY [/bold reverse yellow]", "", "")
        table.add_row("2.1", "  Password Manager", "  Strength, hash, verify", "✓")
        table.add_row("2.2", "  Breach Checker", "  HaveIBeenPwned", "✓")
        table.add_row("2.3", "  Attack Simulator", "  Educational demos", "✓")
        table.add_row("2.4", "  Password Policy", "  Policy validator & advisor", "✓")
        table.add_row("2.5", "  Entropy Visualizer", "  Real-time entropy + crack times", "✓")
        table.add_row("2.6", "  Password Generator", "  Secure passwords & passphrases",  "✓")
        
        table.add_row("", "", "", "")
        table.add_row("", "[bold reverse green] 🛡️  SECURITY AUDIT [/bold reverse green]", "", "")
        table.add_row("3.1", "  SSH Key Auditor", "  Scan SSH keys", "✓")
        table.add_row("3.2", "  SSL/TLS Checker", "  Certificate monitor", "✓")
        table.add_row("3.3", "  Git Secret Scanner", "  Detect secrets", "✓")
        table.add_row("3.4", "  Phishing Detector", "  Email analysis", "✓")
        table.add_row("3.5", "  JWT Analyzer",     "  Decode & audit JWTs",       "✓")
        table.add_row("3.6", "  Config Auditor",   "  Scan for misconfigs",        "✓")
        
        table.add_row("", "", "", "")
        table.add_row("", "[bold reverse blue] 🌐 NETWORK TOOLS [/bold reverse blue]", "", "")
        table.add_row("4.1", "  Port Scanner", "  Network scanning", "✓")
        table.add_row("4.2", "  WHOIS Lookup", "  Domain info", "✓")
        table.add_row("4.3", "  IP Geolocation", "  IP tracking", "✓")
        
        table.add_row("", "", "", "")
        table.add_row("", "[bold reverse blue] 🔍 FORENSICS [/bold reverse blue]", "", "")
        table.add_row("5.1", "  Encoder/Decoder", "  Base64, Hex, Binary, ROT13", "✓")
        table.add_row("5.2", "  Metadata Extractor", "  File analysis & hashing", "✓")
        table.add_row("5.3", "  Steg Detector",    "  Hidden data in images",      "✓")

        table.add_row("", "", "", "")
        table.add_row("", "[bold reverse magenta] 📊 REPORTING [/bold reverse magenta]", "", "")
        table.add_row("6.1", "  Report Generator", "  Export scan results", "✓")

        table.add_row("", "", "", "")
        table.add_row("", "[bold reverse green] 🔌 PLUGINS [/bold reverse green]", "", "")
        table.add_row("7.1", "  Plugin Manager", "  Load & run plugins", "✓")
        
        
        table.add_row("", "", "", "")
        table.add_row("0", "[bold reverse red] EXIT [/bold reverse red]", "  Quit application", "✓")
        
        console.print(table)
        console.print(Align.center(Panel("[green]✓[/green]=Ready [yellow]⚠[/yellow]=Soon", border_style="dim", box=box.SIMPLE)))
    
    # Cryptography
    def hash_file_menu(self):
        console.print("\n" + "="*70)
        console.print(Align.center("[bold cyan]FILE HASHING[/bold cyan]"))
        console.print("="*70 + "\n")
        file_path = Prompt.ask("[cyan]File path[/cyan]")
        try:
            with Progress(SpinnerColumn(), TextColumn("[green]{task.description}"), BarColumn(), TextColumn("{task.percentage:>3.0f}%"), console=console) as progress:
                task = progress.add_task("Hashing...", total=100)
                for i in range(100):
                    progress.update(task, advance=1)
                    time.sleep(0.01)
                file_hash = hash_file(file_path)
            console.print(Panel(f"[bold]File:[/bold] {file_path}\n[bold]SHA-256:[/bold]\n[green]{file_hash}[/green]", title="[bold green]✅ Hash[/bold green]", border_style="green", box=box.DOUBLE))
        except FileNotFoundError:
            console.print("[red]❌ File not found[/red]")
        except Exception as e:
            console.print(f"[red]❌ Error: {e}[/red]")
    
    def verify_integrity_menu(self):
        console.print("\n" + "="*70)
        console.print(Align.center("[bold cyan]INTEGRITY CHECK[/bold cyan]"))
        console.print("="*70 + "\n")
        file1 = Prompt.ask("[cyan]First file[/cyan]")
        file2 = Prompt.ask("[cyan]Second file[/cyan]")
        try:
            with console.status("[green]Comparing...", spinner="dots"):
                result = verify_integrity(file1, file2)
            color = "green" if "intact" in result.lower() else "red"
            icon = "✅" if "intact" in result.lower() else "⚠️"
            console.print(Panel(f"{icon} {result}", border_style=color))
        except Exception as e:
            console.print(f"[red]❌ {e}[/red]")
    
    def aes_encryption_menu(self):
        console.print("\n" + "="*70)
        console.print(Align.center("[bold cyan]AES-256 ENCRYPTION[/bold cyan]"))
        console.print("="*70 + "\n")
        message = Prompt.ask("[cyan]Message[/cyan]")
        try:
            with console.status("[green]Encrypting..."):
                time.sleep(0.3)
                key, ciphertext, plaintext = aes_ed(message)
            console.print(Panel(f"[yellow]Original:[/yellow] {message}\n\n[cyan]Key:[/cyan] {key[:32]}...\n\n[red]Encrypted:[/red] {ciphertext[:50]}...\n\n[green]✅ Decrypted:[/green] {plaintext}", title="[bold green]AES Result[/bold green]", border_style="green", box=box.DOUBLE))
        except Exception as e:
            console.print(f"[red]❌ {e}[/red]")
    
    def rsa_encryption_menu(self):
        console.print("\n" + "="*70)
        console.print(Align.center("[bold cyan]RSA-2048 ENCRYPTION[/bold cyan]"))
        console.print("="*70 + "\n")
        message = Prompt.ask("[cyan]Message[/cyan]")
        try:
            with console.status("[green]Encrypting..."):
                time.sleep(0.3)
                ciphertext, plaintext = rsa_ed(message)
            console.print(Panel(f"[yellow]Original:[/yellow] {message}\n\n[red]Encrypted:[/red] {ciphertext[:50]}...\n\n[green]✅ Decrypted:[/green] {plaintext}", title="[bold green]RSA Result[/bold green]", border_style="green", box=box.DOUBLE))
        except Exception as e:
            console.print(f"[red]❌ {e}[/red]")
    
    # Password Security
    def password_manager_menu(self):
        console.print("\n" + "="*70)
        console.print(Align.center("[bold cyan]PASSWORD MANAGER[/bold cyan]"))
        console.print("="*70 + "\n")
        while True:
            password = getpass("Password: ")
            strength_result = check_strength(password)
            console.print(f"\n{strength_result}")
            if strength_result.startswith("Weak"):
                if not Confirm.ask("[yellow]Try another?[/yellow]", default=True):
                    return
            else:
                break
        with console.status("[green]Hashing..."):
            time.sleep(0.3)
            hashed = hash_pw(password)
        console.print(f"\n[bold]Hash:[/bold]\n[yellow]{hashed.decode()}[/yellow]")
        attempt = getpass("\nVerify: ")
        result = verify_password(attempt, hashed)
        color = "green" if "granted" in result.lower() else "red"
        console.print(f"[{color}]{result}[/{color}]")
    
    def breach_checker_menu(self):
        console.print("\n" + "="*70)
        console.print(Align.center("[bold cyan]BREACH CHECKER[/bold cyan]"))
        console.print("="*70 + "\n")
        console.print(Panel("HaveIBeenPwned • k-anonymity • 500M+ breaches", border_style="cyan"))
        password = getpass("\nPassword: ")
        with Progress(SpinnerColumn(), TextColumn("[yellow]{task.description}"), BarColumn(), console=console) as progress:
            task = progress.add_task("Checking...", total=100)
            for i in range(0, 100, 20):
                progress.update(task, advance=20)
                time.sleep(0.1)
            is_pwned, count = self.breach_checker.check_password(password)
        self.breach_checker.display_result(password, is_pwned, count)
        console.print(f"\n{check_strength(password)}")
    
    def attack_simulator_menu(self):
        console.print("\n" + "="*70)
        console.print(Align.center("[bold red]ATTACK SIMULATOR[/bold red]"))
        console.print("="*70 + "\n")
        console.print(Panel("[red]⚠️  EDUCATIONAL ONLY[/red]\nDemonstrates password attacks", border_style="red"))
        table = Table()
        table.add_column("Opt", style="cyan")
        table.add_column("Type", style="yellow")
        table.add_row("1", "Dictionary Attack")
        table.add_row("2", "Brute Force")
        table.add_row("3", "Rainbow Table")
        table.add_row("0", "Back")
        console.print(table)
        choice = Prompt.ask("[cyan]Choice[/cyan]", choices=["1","2","3","0"])
        if choice == "1":
            self.dictionary_attack_demo()
        elif choice == "2":
            self.brute_force_demo()
        elif choice == "3":
            self.attack_simulator.demonstrate_rainbow_table()
    
    def dictionary_attack_demo(self):
        console.print("\n[bold yellow]Dictionary Attack[/bold yellow]")
        import hashlib
        use_custom = Confirm.ask("Custom password?", default=False)
        target = Prompt.ask("[cyan]Password[/cyan]") if use_custom else "password123"
        if not use_custom:
            console.print(f"[dim]Using: {target}[/dim]")
        target_hash = hashlib.sha256(target.encode()).hexdigest()
        success, pwd, attempts, time_taken = self.attack_simulator.dictionary_attack(target_hash)
        self.attack_simulator.display_attack_results(success, pwd, attempts, time_taken)
    
    def brute_force_demo(self):
        console.print("\n[bold yellow]Brute Force[/bold yellow]")
        use_custom = Confirm.ask("Custom password?", default=False)
        target = Prompt.ask("[cyan]Password (max 4 chars)[/cyan]") if use_custom else "abc"
        if not use_custom:
            console.print(f"[dim]Using: {target}[/dim]")
        if len(target) > 4:
            target = target[:4]
        charset = "lowercase" if Prompt.ask("[cyan]Charset[/cyan] (1=lower, 2=mixed)", choices=["1","2"], default="1") == "1" else "mixed"
        success, pwd, attempts, time_taken = self.attack_simulator.brute_force_attack(target, len(target), charset)
        self.attack_simulator.display_attack_results(success, pwd, attempts, time_taken)
    
    # Security Auditing
    def ssh_auditor_menu(self):
        console.print("\n" + "="*70)
        console.print(Align.center("[bold cyan]SSH AUDITOR[/bold cyan]"))
        console.print("="*70 + "\n")
        if not Confirm.ask("Scan ~/.ssh?", default=True):
            return
        with Progress(SpinnerColumn(), TextColumn("[green]{task.description}"), BarColumn(), console=console) as progress:
            task = progress.add_task("Scanning...", total=100)
            for i in range(0, 100, 25):
                progress.update(task, advance=25)
                time.sleep(0.2)
            keys = self.ssh_auditor.scan_ssh_directory()
            auth_keys = self.ssh_auditor.check_authorized_keys()
        self.ssh_auditor.display_audit_results(keys, auth_keys)
    
    def cert_checker_menu(self):
        console.print("\n" + "="*70)
        console.print(Align.center("[bold cyan]SSL/TLS CHECKER[/bold cyan]"))
        console.print("="*70 + "\n")
        urls = []
        while True:
            url = Prompt.ask("[cyan]URL (Enter to finish)[/cyan]", default="")
            if not url:
                break
            urls.append(url)
        if urls:
            results = self.cert_checker.check_multiple_sites(urls)
            self.cert_checker.display_results(results)
    
    def git_scanner_menu(self):
        console.print("\n" + "="*70)
        console.print(Align.center("[bold cyan]GIT SECRET SCANNER[/bold cyan]"))
        console.print("="*70 + "\n")
        console.print(Panel("Scans for: API keys • Passwords • Tokens • AWS credentials", border_style="yellow"))
        directory = Prompt.ask("[cyan]Directory[/cyan]", default=".")
        findings = self.git_scanner.scan_directory(directory)
        self.git_scanner.display_findings(findings)
    
    def phishing_detector_menu(self):
        console.print("\n" + "="*70)
        console.print(Align.center("[bold cyan]PHISHING DETECTOR[/bold cyan]"))
        console.print("="*70 + "\n")
        use_sample = Confirm.ask("Use sample email?", default=True)
        if use_sample:
            sender = "security@paypa1-verify.tk"
            subject = "URGENT: Verify account"
            email_body = "Dear Customer,\nUnusual activity detected.\nClick: http://192.168.1.1/verify\nAccount will be suspended in 24h."
            console.print("[dim]Sample loaded[/dim]")
        else:
            sender = Prompt.ask("[cyan]Sender[/cyan]")
            subject = Prompt.ask("[cyan]Subject[/cyan]")
            console.print("[cyan]Body (Ctrl+D when done)[/cyan]")
            lines = []
            try:
                while True:
                    lines.append(input())
            except EOFError:
                pass
            email_body = "\n".join(lines)
        with console.status("[yellow]Analyzing..."):
            time.sleep(0.5)
            risk_score, indicators = self.phishing_detector.analyze_email(email_body, sender, subject)
        self.phishing_detector.display_analysis(risk_score, indicators, sender, subject)
    
    # Network
    def port_scanner_menu(self):
        try:
            from modules.network.port_scanner import run_port_scanner
            run_port_scanner()
        except ImportError:
            console.print(Panel("[yellow]Network modules not yet implemented[/yellow]\nSee ADVANCED_FEATURES_GUIDE_PART1.md", border_style="yellow"))
    def whois_menu(self):
        console.print("\n" + "="*70)
        console.print(Align.center("[bold cyan]WHOIS LOOKUP[/bold cyan]"))
        console.print("="*70 + "\n")
        domain = Prompt.ask("[cyan]Enter domain (e.g. google.com)[/cyan]")
        domain = domain.replace("http://", "").replace("https://", "").split("/")[0]
        with console.status(f"[green]Querying WHOIS for {domain}..."):
            whois_data = self.whois.query_whois(domain)
            parsed = self.whois.parse_whois_data(whois_data)
        self.whois.display_whois_info(domain, whois_data, parsed)
    
    def ip_geolocation_menu(self):
        console.print("\n" + "="*70)
        console.print(Align.center("[bold cyan]IP GEOLOCATION[/bold cyan]"))
        console.print("="*70 + "\n")
        console.print("[dim]Leave blank to look up your own public IP[/dim]\n")
        ip = Prompt.ask("[cyan]Enter IP address[/cyan]", default="")
        with console.status(f"[green]Looking up {ip or 'your IP'}..."):
            data = self.ip_geo.lookup_ip(ip)
        self.ip_geo.display_location_info(data)

    def password_policy_menu(self):
        console.print("\n" + "="*70)
        console.print(Align.center("[bold cyan]PASSWORD POLICY ADVISOR[/bold cyan]"))
        console.print("="*70 + "\n")
        from modules.password.password_policy import run_password_policy
        run_password_policy()

    def encoder_decoder_menu(self):
        console.print("\n" + "="*70)
        console.print(Align.center("[bold cyan]ENCODER / DECODER[/bold cyan]"))
        console.print("="*70 + "\n")
        from modules.forensics.encoder_decoder import run_encoder_decoder
        run_encoder_decoder()

    def metadata_extractor_menu(self):
        console.print("\n" + "="*70)
        console.print(Align.center("[bold cyan]FILE METADATA EXTRACTOR[/bold cyan]"))
        console.print("="*70 + "\n")
        file_path = Prompt.ask("[cyan]Enter file path[/cyan]")
        with console.status("[green]Analyzing..."):
            metadata = self.metadata_extractor.extract_metadata(file_path)
        self.metadata_extractor.display_metadata(metadata)

    def report_generator_menu(self):
        console.print("\n" + "="*70)
        console.print(Align.center("[bold cyan]REPORT GENERATOR[/bold cyan]"))
        console.print("="*70 + "\n")
        from modules.reporting.report_generator import run_report_generator
        run_report_generator()

    def plugin_manager_menu(self):
        console.print("\n" + "="*70)
        console.print(Align.center("[bold cyan]PLUGIN MANAGER[/bold cyan]"))
        console.print("="*70 + "\n")
        from modules.plugins.plugins_manager import run_plugins_manager
        run_plugins_manager()
        
        
        
        
        
    def jwt_analyzer_menu(self):
        console.print("\n" + "="*70)
        console.print(Align.center("[bold cyan]JWT ANALYZER[/bold cyan]"))
        console.print("="*70 + "\n")
        console.print("[dim]Paste your JWT token below (eyJ...)[/dim]\n")
        token = Prompt.ask("[cyan]JWT Token[/cyan]")
        with console.status("[green]Analyzing..."):
            result = self.jwt_analyzer.analyze(token)
        self.jwt_analyzer.display_analysis(result)

    def config_auditor_menu(self):
        console.print("\n" + "="*70)
        console.print(Align.center("[bold cyan]CONFIG FILE AUDITOR[/bold cyan]"))
        console.print("="*70 + "\n")
        directory = Prompt.ask("[cyan]Directory to scan[/cyan]", default=".")
        findings = self.config_auditor.scan_directory(directory)
        self.config_auditor.display_findings(findings)

    def steg_detector_menu(self):
        console.print("\n" + "="*70)
        console.print(Align.center("[bold cyan]STEGANOGRAPHY DETECTOR[/bold cyan]"))
        console.print("="*70 + "\n")
        file_path = Prompt.ask("[cyan]Image file path[/cyan]")
        with console.status("[green]Analyzing..."):
            result = self.steg_detector.analyze(file_path)
        self.steg_detector.display_results(result)

    def entropy_visualizer_menu(self):
        console.print("\n" + "="*70)
        console.print(Align.center("[bold cyan]ENTROPY VISUALIZER[/bold cyan]"))
        console.print("="*70 + "\n")
        from getpass import getpass
        password = getpass("Password to analyze: ")
        self.entropy_visualizer.display(password)

    def password_generator_menu(self):
        self.password_generator.run_interactive()
        
    # Main Loop
    def run(self):
        self.display_welcome_screen()
        while self.running:
            console.clear()
            self.display_main_menu()
            choice = Prompt.ask("\n[bold cyan]➤ Choice[/bold cyan]", default="0").strip().lower()
            try:
                self.handle_choice(choice)
            except KeyboardInterrupt:
                console.print("\n[yellow]Cancelled[/yellow]")
            except Exception as e:
                console.print(f"\n[red]❌ {e}[/red]")
            if self.running and choice != "0":
                Prompt.ask("\n[dim]Press Enter[/dim]", default="")
    
    def handle_choice(self, choice):
        if choice == "1.1":
            self.hash_file_menu()
        elif choice == "1.2":
            self.verify_integrity_menu()
        elif choice == "1.3":
            self.aes_encryption_menu()
        elif choice == "1.4":
            self.rsa_encryption_menu()
        elif choice == "2.1":
            self.password_manager_menu()
        elif choice == "2.2":
            self.breach_checker_menu()
        elif choice == "2.3":
            self.attack_simulator_menu()
        elif choice == "2.4":
            self.password_policy_menu()
        elif choice == "2.5":
            self.entropy_visualizer_menu()
        elif choice == "2.6":
            self.password_generator_menu()
        elif choice == "3.1":
            self.ssh_auditor_menu()
        elif choice == "3.2":
            self.cert_checker_menu()
        elif choice == "3.3":
            self.git_scanner_menu()
        elif choice == "3.4":
            self.phishing_detector_menu()
        elif choice == "3.5":
            self.jwt_analyzer_menu()
        elif choice == "3.6":
            self.config_auditor_menu()
        elif choice == "4.1":
            self.port_scanner_menu()
        elif choice == "4.2":
            self.whois_menu()
        elif choice == "4.3":
            self.ip_geolocation_menu()
        elif choice == "5.1":
            self.encoder_decoder_menu()
        elif choice == "5.2":
            self.metadata_extractor_menu()
        elif choice == "5.3":
            self.steg_detector_menu()
        elif choice == "6.1":
            self.report_generator_menu()
        elif choice == "7.1":
            self.plugin_manager_menu()
        elif choice == "0":
            self.exit_application()
        else:
            console.print(Panel(f"[red]Invalid: {choice}[/red]\n[yellow]Try: 1.1, 2.2, etc.[/yellow]", border_style="red"))
    
    def exit_application(self):
        console.clear()
        console.print(Panel(Align.center("[bold yellow]Thank you for using Cyber Swiss Knife v3.0![/bold yellow]\n\n[green]✓ Secure shutdown[/green]\n\n[cyan]Stay safe! 🔐[/cyan]\n\n[dim]Use responsibly and ethically[/dim]"), title="[bold cyan]Goodbye[/bold cyan]", border_style="cyan", box=box.DOUBLE, padding=(2,4)))
        self.running = False

def main():
    try:
        app = CyberSwissKnife()
        app.run()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Fatal: {e}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main()
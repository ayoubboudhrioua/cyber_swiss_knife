import os
import re
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import track

console = Console()

class GitSecretScanner:
    """Scan git repositories for accidentally committed secrets"""
    
    def __init__(self):
        # Patterns for common secrets
        self.patterns = {
            'AWS Access Key': r'AKIA[0-9A-Z]{16}',
            'AWS Secret Key': r'aws(.{0,20})?[\'"][0-9a-zA-Z/+]{40}[\'"]',
            'GitHub Token': r'ghp_[0-9a-zA-Z]{36}',
            'GitHub OAuth': r'gho_[0-9a-zA-Z]{36}',
            'Generic API Key': r'api[_-]?key[\'"\s]*[:=][\'"\s]*[0-9a-zA-Z]{32,}',
            'Private Key': r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
            'Password in URL': r'[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}',
            'Slack Token': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}',
            'Google API': r'AIza[0-9A-Za-z\\-_]{35}',
            'Heroku API': r'[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
            'Generic Secret': r'secret[\'"\s]*[:=][\'"\s]*[0-9a-zA-Z]{8,}',
            'Password Variable': r'password[\'"\s]*[:=][\'"\s]*[0-9a-zA-Z]{8,}',
        }
        
        # Files to ignore
        self.ignore_extensions = {'.jpg', '.png', '.gif', '.pdf', '.zip', '.exe', '.bin'}
        self.ignore_dirs = {'.git', 'node_modules', '__pycache__', 'venv', '.env'}
    
    def scan_directory(self, directory):
        """Scan directory for secrets"""
        directory = Path(directory)
        findings = []
        
        if not directory.exists():
            console.print(f"[red]Directory not found: {directory}[/red]")
            return findings
        
        # Get all files
        all_files = []
        for root, dirs, files in os.walk(directory):
            # Remove ignored directories
            dirs[:] = [d for d in dirs if d not in self.ignore_dirs]
            
            for file in files:
                file_path = Path(root) / file
                if file_path.suffix not in self.ignore_extensions:
                    all_files.append(file_path)
        
        # Scan files
        for file_path in track(all_files, description="Scanning files..."):
            file_findings = self._scan_file(file_path)
            findings.extend(file_findings)
        
        return findings
    
    def _scan_file(self, file_path):
        """Scan individual file for secrets"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
                for secret_type, pattern in self.patterns.items():
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    
                    for match in matches:
                        # Get line number
                        line_num = content[:match.start()].count('\n') + 1
                        
                        # Get the line content
                        lines = content.split('\n')
                        line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                        
                        finding = {
                            'file': str(file_path),
                            'type': secret_type,
                            'line': line_num,
                            'content': line_content.strip()[:100],  # First 100 chars
                            'matched': match.group()[:50]  # Matched secret (truncated)
                        }
                        
                        findings.append(finding)
        
        except Exception as e:
            # Silently skip files that can't be read
            pass
        
        return findings
    
    def display_findings(self, findings):
        """Display scan results"""
        
        if not findings:
            console.print(Panel(
                "[bold green]✅ No secrets detected![/bold green]\n"
                "[dim]Your repository appears clean.[/dim]",
                title="Scan Complete",
                border_style="green"
            ))
            return
        
        # Group by type
        by_type = {}
        for finding in findings:
            secret_type = finding['type']
            if secret_type not in by_type:
                by_type[secret_type] = []
            by_type[secret_type].append(finding)
        
        # Display summary
        console.print(Panel(
            f"[bold red]🚨 Found {len(findings)} potential secrets![/bold red]\n"
            f"[yellow]Secret types detected: {len(by_type)}[/yellow]",
            title="Scan Results",
            border_style="red"
        ))
        
        # Display detailed table
        table = Table(title="\n📁 Detected Secrets", show_header=True, header_style="bold magenta")
        table.add_column("File", style="cyan", width=30)
        table.add_column("Type", style="yellow", width=20)
        table.add_column("Line", style="blue", width=6)
        table.add_column("Preview", style="red", width=40)
        
        for finding in findings[:50]:  # Limit to first 50
            table.add_row(
                Path(finding['file']).name,  # Just filename
                finding['type'],
                str(finding['line']),
                finding['content'][:40] + "..." if len(finding['content']) > 40 else finding['content']
            )
        
        if len(findings) > 50:
            table.add_row("...", "...", "...", f"... and {len(findings) - 50} more")
        
        console.print(table)
        
        # Recommendations
        console.print("\n[bold red]⚠️  IMMEDIATE ACTIONS REQUIRED:[/bold red]")
        console.print("  1. [red]DO NOT commit these changes if not yet pushed[/red]")
        console.print("  2. Remove sensitive data from files")
        console.print("  3. If already committed: git filter-branch or BFG Repo-Cleaner")
        console.print("  4. Rotate all exposed credentials immediately")
        console.print("  5. Use .gitignore for config files")
        console.print("  6. Consider using environment variables or secret managers")
        
        # Stats by type
        console.print("\n[bold]Secrets by Type:[/bold]")
        for secret_type, items in sorted(by_type.items(), key=lambda x: len(x[1]), reverse=True):
            console.print(f"  • {secret_type}: {len(items)}")

# Usage
def scan_for_secrets():
    scanner = GitSecretScanner()
    
    console.print("[bold]Git Secret Scanner[/bold]\n")
    directory = console.input("[cyan]Enter directory to scan (default: current directory): [/cyan]").strip()
    
    if not directory:
        directory = "."
    
    console.print(f"\n[yellow]Scanning {directory}...[/yellow]\n")
    
    findings = scanner.scan_directory(directory)
    scanner.display_findings(findings)
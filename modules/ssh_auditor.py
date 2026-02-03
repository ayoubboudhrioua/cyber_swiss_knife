
import os
import re
from pathlib import Path
from datetime import datetime, timedelta
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

class SSHKeyAuditor:
    """Audit SSH keys for security issues"""
    
    def __init__(self):
        self.ssh_dir = Path.home() / '.ssh'
        self.weak_key_types = ['ssh-dss', 'ssh-rsa 1024']
        self.recommended_types = ['ssh-ed25519', 'ecdsa-sha2-nistp256', 'ssh-rsa 4096']
    
    def scan_ssh_directory(self):
        """Scan .ssh directory for keys"""
        if not self.ssh_dir.exists():
            console.print("[yellow]No .ssh directory found[/yellow]")
            return []
        
        keys = []
        
        # Look for private keys
        for file in self.ssh_dir.iterdir():
            if file.is_file() and not file.name.endswith('.pub'):
                # Check if it's a private key
                try:
                    with open(file, 'r') as f:
                        first_line = f.readline()
                        if 'PRIVATE KEY' in first_line:
                            key_info = self._analyze_key(file)
                            keys.append(key_info)
                except:
                    continue
        
        return keys
    
    def _analyze_key(self, key_path):
        """Analyze individual SSH key"""
        info = {
            'path': str(key_path),
            'name': key_path.name,
            'issues': [],
            'risk_score': 0
        }
        
        # Check file permissions
        stat_info = os.stat(key_path)
        perms = oct(stat_info.st_mode)[-3:]
        
        if perms != '600':
            info['issues'].append(f"Insecure permissions: {perms} (should be 600)")
            info['risk_score'] += 30
        
        # Check key age
        created_time = datetime.fromtimestamp(stat_info.st_ctime)
        age_days = (datetime.now() - created_time).days
        
        if age_days > 365:
            info['issues'].append(f"Key is {age_days} days old (>1 year)")
            info['risk_score'] += 15
        
        info['age_days'] = age_days
        
        # Try to determine key type
        try:
            with open(key_path, 'r') as f:
                content = f.read()
                
                # Detect key type
                if 'RSA PRIVATE KEY' in content:
                    info['type'] = 'RSA'
                    # Check bit length (simplified)
                    if 'BEGIN RSA PRIVATE KEY' in content:
                        # Rough estimate based on file size
                        if len(content) < 1500:
                            info['issues'].append("Possibly weak RSA key (<2048 bits)")
                            info['risk_score'] += 40
                
                elif 'DSA PRIVATE KEY' in content:
                    info['type'] = 'DSA'
                    info['issues'].append("DSA keys are deprecated and insecure")
                    info['risk_score'] += 50
                
                elif 'EC PRIVATE KEY' in content:
                    info['type'] = 'ECDSA'
                
                elif 'OPENSSH PRIVATE KEY' in content:
                    info['type'] = 'Ed25519 (likely)'
                
                else:
                    info['type'] = 'Unknown'
                
                # Check if encrypted
                if 'ENCRYPTED' not in content and 'Proc-Type: 4,ENCRYPTED' not in content:
                    info['issues'].append("Private key is not password-protected")
                    info['risk_score'] += 25
        
        except Exception as e:
            info['issues'].append(f"Could not analyze key: {e}")
        
        return info
    
    def check_authorized_keys(self):
        """Check authorized_keys file"""
        auth_keys_path = self.ssh_dir / 'authorized_keys'
        
        if not auth_keys_path.exists():
            return None
        
        issues = []
        
        # Check permissions
        stat_info = os.stat(auth_keys_path)
        perms = oct(stat_info.st_mode)[-3:]
        
        if perms not in ['600', '644']:
            issues.append(f"Insecure permissions: {perms}")
        
        # Count keys
        try:
            with open(auth_keys_path, 'r') as f:
                keys = [line for line in f if line.strip() and not line.startswith('#')]
                key_count = len(keys)
                
                # Check for old key types
                weak_keys = []
                for i, key in enumerate(keys, 1):
                    if key.startswith('ssh-dss'):
                        weak_keys.append(f"Key {i}: DSA (deprecated)")
                    elif 'ssh-rsa' in key:
                        # Try to estimate bit length
                        parts = key.split()
                        if len(parts) > 1 and len(parts[1]) < 500:
                            weak_keys.append(f"Key {i}: Possibly weak RSA")
                
                if weak_keys:
                    issues.extend(weak_keys)
        
        except Exception as e:
            issues.append(f"Error reading file: {e}")
            key_count = 0
        
        return {
            'path': str(auth_keys_path),
            'key_count': key_count,
            'issues': issues
        }
    
    def display_audit_results(self, keys, auth_keys_info):
        """Display audit results beautifully"""
        
        console.print(Panel("[bold cyan]🔑 SSH Key Security Audit[/bold cyan]", border_style="cyan"))
        
        # Private Keys Table
        if keys:
            table = Table(title="\n📁 Private Keys Found", show_header=True, header_style="bold magenta")
            table.add_column("Key Name", style="cyan")
            table.add_column("Type", style="yellow")
            table.add_column("Age (days)", style="blue")
            table.add_column("Risk", style="red")
            table.add_column("Issues", style="white")
            
            for key in keys:
                risk_level = "🟢 Low" if key['risk_score'] < 20 else "🟡 Medium" if key['risk_score'] < 50 else "🔴 High"
                issues_str = "\n".join(key['issues']) if key['issues'] else "None"
                
                table.add_row(
                    key['name'],
                    key.get('type', 'Unknown'),
                    str(key.get('age_days', 'N/A')),
                    risk_level,
                    issues_str[:50] + "..." if len(issues_str) > 50 else issues_str
                )
            
            console.print(table)
        else:
            console.print("\n[yellow]No private keys found in ~/.ssh/[/yellow]")
        
        # Authorized Keys Info
        if auth_keys_info:
            console.print(f"\n[bold]📋 Authorized Keys:[/bold]")
            console.print(f"  Location: {auth_keys_info['path']}")
            console.print(f"  Total Keys: {auth_keys_info['key_count']}")
            
            if auth_keys_info['issues']:
                console.print("\n  [red]Issues:[/red]")
                for issue in auth_keys_info['issues']:
                    console.print(f"    • {issue}")
        
        # Recommendations
        console.print("\n[bold cyan]🛡️  Security Recommendations:[/bold cyan]")
        console.print("  1. Use Ed25519 keys: ssh-keygen -t ed25519 -C 'your_email@example.com'")
        console.print("  2. Protect private keys with passphrases")
        console.print("  3. Set correct permissions: chmod 600 ~/.ssh/id_*")
        console.print("  4. Rotate keys annually")
        console.print("  5. Remove unused authorized_keys entries")

# Usage
def run_ssh_audit():
    auditor = SSHKeyAuditor()
    
    console.print("[bold]Starting SSH Key Audit...[/bold]\n")
    
    keys = auditor.scan_ssh_directory()
    auth_keys = auditor.check_authorized_keys()
    
    auditor.display_audit_results(keys, auth_keys)
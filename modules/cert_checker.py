import ssl
import socket
from datetime import datetime, timedelta
from rich.console import Console
from rich.table import Table
from urllib.parse import urlparse

console = Console()

class CertificateChecker:
    """Check SSL/TLS certificates for expiration and security"""
    
    def __init__(self):
        self.warning_days = 30  # Warn if cert expires within 30 days
    
    def check_certificate(self, hostname, port=443):
        """
        Check SSL certificate for a given hostname
        Returns: dict with cert info
        """
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
            
            # Parse certificate info
            info = self._parse_certificate(cert, hostname)
            return info
            
        except socket.gaierror:
            return {'error': f'Could not resolve hostname: {hostname}'}
        except socket.timeout:
            return {'error': f'Connection timeout to {hostname}:{port}'}
        except ssl.SSLError as e:
            return {'error': f'SSL Error: {str(e)}'}
        except Exception as e:
            return {'error': f'Error: {str(e)}'}
    
    def _parse_certificate(self, cert, hostname):
        """Parse certificate information"""
        info = {
            'hostname': hostname,
            'subject': dict(x[0] for x in cert['subject']),
            'issuer': dict(x[0] for x in cert['issuer']),
            'version': cert['version'],
            'serialNumber': cert['serialNumber'],
            'notBefore': cert['notBefore'],
            'notAfter': cert['notAfter'],
            'san': [],
            'issues': []
        }
        
        # Parse Subject Alternative Names
        if 'subjectAltName' in cert:
            info['san'] = [x[1] for x in cert['subjectAltName']]
        
        # Check expiration
        expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        days_until_expiry = (expiry_date - datetime.now()).days
        
        info['expires_in_days'] = days_until_expiry
        info['expiry_date'] = expiry_date
        
        if days_until_expiry < 0:
            info['issues'].append(f"EXPIRED {abs(days_until_expiry)} days ago!")
            info['status'] = '🔴 EXPIRED'
        elif days_until_expiry < self.warning_days:
            info['issues'].append(f"Expires soon ({days_until_expiry} days)")
            info['status'] = '🟡 WARNING'
        else:
            info['status'] = '🟢 VALID'
        
        # Check if hostname matches certificate
        if not self._verify_hostname(hostname, info['subject'].get('commonName', ''), info['san']):
            info['issues'].append('Hostname mismatch')
        
        return info
    
    def _verify_hostname(self, hostname, cn, san_list):
        """Verify hostname matches certificate"""
        if hostname == cn:
            return True
        
        if hostname in san_list:
            return True
        
        # Check wildcards
        for san in san_list:
            if san.startswith('*.'):
                domain = san[2:]
                if hostname.endswith(domain):
                    return True
        
        return False
    
    def check_multiple_sites(self, urls):
        """Check multiple websites"""
        results = []
        
        with console.status("[bold green]Checking certificates...") as status:
            for url in urls:
                # Parse URL to get hostname
                if not url.startswith('http'):
                    url = 'https://' + url
                
                parsed = urlparse(url)
                hostname = parsed.netloc or parsed.path
                
                status.update(f"Checking {hostname}...")
                result = self.check_certificate(hostname)
                results.append(result)
        
        return results
    
    def display_results(self, results):
        """Display certificate check results"""
        
        table = Table(title="🔒 SSL/TLS Certificate Status", show_header=True, header_style="bold magenta")
        table.add_column("Hostname", style="cyan", width=25)
        table.add_column("Status", style="yellow", width=12)
        table.add_column("Expires In", style="blue", width=15)
        table.add_column("Issuer", style="green", width=20)
        table.add_column("Issues", style="red")
        
        for result in results:
            if 'error' in result:
                table.add_row(
                    result.get('hostname', 'Unknown'),
                    "❌ ERROR",
                    "-",
                    "-",
                    result['error']
                )
            else:
                expires_str = f"{result['expires_in_days']} days"
                issuer = result['issuer'].get('organizationName', 'Unknown')
                issues_str = "\n".join(result['issues']) if result['issues'] else "None"
                
                table.add_row(
                    result['hostname'],
                    result['status'],
                    expires_str,
                    issuer[:20],
                    issues_str
                )
        
        console.print(table)
        
        # Summary
        expired = sum(1 for r in results if r.get('expires_in_days', 0) < 0)
        warning = sum(1 for r in results if 0 <= r.get('expires_in_days', 999) < self.warning_days)
        valid = sum(1 for r in results if r.get('expires_in_days', 999) >= self.warning_days)
        
        console.print(f"\n[bold]Summary:[/bold]")
        console.print(f"  🔴 Expired: {expired}")
        console.print(f"  🟡 Expiring Soon: {warning}")
        console.print(f"  🟢 Valid: {valid}")

# Usage
def check_certificates():
    checker = CertificateChecker()
    
    console.print("[bold]Enter websites to check (one per line, empty to finish):[/bold]")
    
    urls = []
    while True:
        url = console.input("[cyan]Website: [/cyan]").strip()
        if not url:
            break
        urls.append(url)
    
    if urls:
        results = checker.check_multiple_sites(urls)
        checker.display_results(results)
    else:
        console.print("[yellow]No websites provided[/yellow]")
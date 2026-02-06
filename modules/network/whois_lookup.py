import socket
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

class WhoisLookup:
    """WHOIS information lookup tool"""
    WHOIS_SERVERS = {
        'com': 'whois.verisign-grs.com',
        'net': 'whois.verisign-grs.com',
        'org': 'whois.pir.org',
        'io': 'whois.nic.io',
        'ai': 'whois.nic.ai',
        'default': 'whois.iana.org'
    }
    def query_whois(self,domain,server=None):
        """Query WHOIS server for domain information"""
        if server is None:
            #determine server based on TLD
            tld = domain.split('.')[-1]
            server = self.WHOIS_SERVERS.get(tld,self.WHOIS_SERVERS["default"])
        try:
            # Connect to WHOIS server
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((server, 43))
            
            # Send query
            sock.send(f"{domain}\r\n".encode())
            
            # Receive response
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            sock.close()
            
            return response.decode('utf-8',errors='ignore')
        except Exception as e:
            return f"Error: {e}"
    def parse_whois_data(self,whois_text):
        """Parse WHOIS data and extract key information"""
        info = {}
        # common fields to extract
        fields = {
            'Domain Name': ['Domain Name', 'domain'],
            'Registrar': ['Registrar', 'registrar'],
            'Creation Date': ['Creation Date', 'created'],
            'Expiration Date': ['Expiration Date', 'expires', 'Expiry Date'],
            'Updated Date': ['Updated Date', 'updated', 'Last Updated'],
            'Status': ['Status', 'Domain Status'],
            'Name Servers': ['Name Server', 'nserver'],
        }
        lines = whois_text.split('\n')
        for line in lines:
            line = line.strip()
            if ':' in line:
                key,value = line.split(':',1)
                key = key.strip()
                value = value.strip()
                
                # match against known fields
                for field_name, patterns in fields.items():
                    if any(pattern.lower() in key.lower() for pattern in patterns):
                        if field_name not in info:
                            info[field_name] = []
                        info[field_name].append(value)
                        
        return info
    def display_whois_info(self,domain,whois_data,parsed_info):
        """
        Display WHOIS information beautifully
        """
        console.print(f"\n[bold cyan]🌐 WHOIS Information for {domain}[/bold cyan]")
        
        if parsed_info:
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Field", style="cyan", width=20)
            table.add_column("Value", style="yellow")
            
            for field, values in parsed_info.items():
                if values:
                    # Show first value or join multiple
                    if field == 'Name Servers':
                        value = '\n'.join(values[:5])  # Limit to 5 NS
                    else:
                        value = values[0]
                    
                    table.add_row(field, value)
            
            console.print(table)
        
        # Show raw data option
        if console.input("\n[dim]Show raw WHOIS data? (y/n): [/dim]").lower() == 'y':
            console.print(Panel(
                whois_data,
                title="Raw WHOIS Data",
                border_style="dim"
            ))


def run_whois_lookup():
    """Interactive WHOIS lookup"""
    lookup = WhoisLookup()
    
    console.print("\n[bold cyan]🌐 WHOIS Domain Lookup[/bold cyan]")
    domain = console.input("\n[cyan]Enter domain name: [/cyan]").strip()
    
    # Remove http/https if present
    domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
    
    with console.status(f"[bold green]Querying WHOIS for {domain}..."):
        whois_data = lookup.query_whois(domain)
        parsed = lookup.parse_whois_data(whois_data)
    
    lookup.display_whois_info(domain, whois_data, parsed)
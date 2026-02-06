import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

class IPGeolocation:
    """Ip Geolocation lookip using free API"""
    
    def __init__(self):
        # using ip-api.com (free, no key required)
        self.api_url = "http://ip-api.com/json/{}"
        
    def lookup_ip(self,ip_address=""):
        """lookup geolocation information for an IP 
        if no IP provided shows info for current public IP"""
        try:
            url = self.api_url.format(ip_address)
            response = requests.get(url,timeout=10)
            response.raise_for_status()
            
            data = response.json()
            if data.get('status') == 'success':
                return data
            else:
                return {'error': data.get('message','Lookup failed')}
        except requests.RequestException as e:
            return {'error': f"Request failed: {e}"}
    
    def display_location_info(self,data):
        """Display IP geolocation information"""
        if 'error' in data:
            console.print(f"[red]❌ Error: {data['error']}[/red]")
            return
        # Create info table
        table = Table(
            title=f"📍 IP Geolocation: {data.get('query', 'N/A')}",
            show_header=True,
            header_style="bold magenta"
        )
        table.add_column("Field", style="cyan", width=20)
        table.add_column("Value", style="yellow")
        
        # Add data
        fields = {
            'Country': data.get('country', 'N/A'),
            'Country Code': data.get('countryCode', 'N/A'),
            'Region': data.get('regionName', 'N/A'),
            'City': data.get('city', 'N/A'),
            'ZIP Code': data.get('zip', 'N/A'),
            'Latitude': str(data.get('lat', 'N/A')),
            'Longitude': str(data.get('lon', 'N/A')),
            'Timezone': data.get('timezone', 'N/A'),
            'ISP': data.get('isp', 'N/A'),
            'Organization': data.get('org', 'N/A'),
            'AS Number': data.get('as', 'N/A'),
        }
        
        for field, value in fields.items():
            table.add_row(field, value)
        
        console.print(table)
        
        # Map link
        if data.get('lat') and data.get('lon'):
            map_url = f"https://www.google.com/maps?q={data['lat']},{data['lon']}"
            console.print(f"\n[cyan]🗺️  Map: {map_url}[/cyan]")
            

def run_ip_geolocation():
    """Interactive IP geolocation lookup"""
    geo = IPGeolocation()
    
    console.print("\n[bold cyan]📍 IP Geolocation Lookup[/bold cyan]")
    console.print("[dim]Leave blank to check your current public IP[/dim]\n")
    
    ip = console.input("[cyan]Enter IP address: [/cyan]").strip()
    
    with console.status(f"[bold green]Looking up {ip or 'your IP'}..."):
        data = geo.lookup_ip(ip)
    
    geo.display_location_info(data)
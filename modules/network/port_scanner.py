import socket
import concurrent.futures
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress,SpinnerColumn,BarColumn,TextColumn,TimeElapsedColumn
console = Console()
class PortScanner:
    """Professional port scanner with service detection Eductaional tool 
    for Network security assessment
    """
    def __init__(self):
        self.common_ports = {
            20: "FTP Data",
            21: "FTP Control",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            67: "DHCP",
            68: "DHCP",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            143: "IMAP",
            5432: "PostgreSQL",
            3306: "MySQL",
            3389: "RDP",
            5900: "VNC",
            8080: "HTTP Proxy",
            8443: "HTTPS Alt"
        }
    def scan_port(self,host,port,timeout=1):
        """Scan a single port on a host"""
        try:
            sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host,port))
            sock.close()
            
            is_open = (result == 0)
            service = self.common_ports.get(port,"unknown")
            
            #try to grab banner for service authentification
            if is_open:
                try:
                    service = self.grab_banner(host,port)
                except:
                    service = self.common_ports.get(port,"unknown")
            return (port,is_open,service)
        except socket.error :
            return (port,False,"Error")
    def grab_banner(self,host,port,timeout=2):
        """Attempt to grab service banner for identification """
        try:
            sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host,port))
            
            #try to receive banner data
            sock.send(b'\r\n')
            banner = sock.recv(1024).decode('utf-8',errors='ignore').strip()
            sock.close()
            
            if banner:
                #extract service name from banner
                if 'SSH' in banner:
                    return f"SSH ({banner[:30]})"
                elif 'HTTP' in banner or 'Apache' in banner or 'nginx' in banner:
                    return f'HTTP({banner[:30]})'
                else:
                    return banner[:40]
            return self.common_ports.get(port,"unknown")
        except:
            return self.common_ports.get(port,"unknown")
    def scan_host(self,host,ports=None,max_workers=100):
        """Scan multiple ports on a host"""
        if ports is None:
            ports = list(self.common_ports.keys())
            
        console.print(f"\n[bold cyan] 🔍 Port Scan Results for {host}[/bold cyan]")
        console.print(f"[dim]Scanning {len(ports)} ports...[/dim]\n")
        
        start_time = datetime.now()
        open_ports = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task(
                f"[cyan]Scanning {host}...",
                total=len(ports)
            )
            
            #Concurrent scanning
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_port = {
                    executor.submit(self.scan_port,host,port):port for port in ports
                }
                for future in concurrent.futures.as_completed(future_to_port):
                    port,is_open,service = future.result()
                    if is_open:
                        open_ports.append((port,service))
                    progress.advance(task)
        end_time = datetime.now()
        scan_duration = (end_time - start_time).total_seconds()
        
        #Display results
        self.display_results(host,open_ports,scan_duration,len(ports))
        
        return open_ports
    def scan_range(self,host,start_port,end_port):
        """Scan a range of ports"""
        ports = range(start_port,end_port+1)
        return self.scan_host(host,ports)
    def display_results(self,host,open_ports,duration,total_scanned):
        """Display scan results in a beautiful table"""
        
        if not open_ports:
            console.print("[yellow]No open ports found[/yellow]")
            return
        
        # Create results table
        table = Table(
            title=f"\n✅ Open Ports on {host}",
            show_header=True,
            header_style="bold magenta"
        )
        table.add_column("Port", style="cyan", justify="right", width=8)
        table.add_column("State", style="green", width=10)
        table.add_column("Service", style="yellow")
        
        for port, service in sorted(open_ports):
            table.add_row(str(port), "OPEN", service)
        
        console.print(table)
        
        # Summary
        console.print(f"\n[bold]Summary:[/bold]")
        console.print(f"  • Total ports scanned: {total_scanned}")
        console.print(f"  • Open ports found: {len(open_ports)}")
        console.print(f"  • Scan duration: {duration:.2f} seconds")
        console.print(f"  • Scan rate: {total_scanned/duration:.0f} ports/sec")
        
        # Security recommendations
        console.print("\n[bold cyan]🛡️  Security Notes:[/bold cyan]")
        
        dangerous_ports = {
            21: "FTP - Consider using SFTP instead",
            23: "Telnet - Unencrypted, use SSH",
            3389: "RDP - Ensure strong passwords and limit access",
            5900: "VNC - Often misconfigured",
        }
        
        for port, service in open_ports:
            if port in dangerous_ports:
                console.print(f"  ⚠️  Port {port} ({service}): {dangerous_ports[port]}")
                



#usage function :
def run_port_scanner():
    """Interactive function to run the port scanner"""
    scanner = PortScanner()
    
    console.print("\n[bold cyan]🔍 Network Port Scanner[/bold cyan]")
    console.print("[yellow]⚠️  Only scan systems you own or have permission to test![/yellow]\n")
    
    # Get target
    host = console.input("[cyan]Enter target IP or hostname: [/cyan]").strip()
    
    # Validate host
    try:
        socket.gethostbyname(host)
    except socket.gaierror:
        console.print(f"[red]❌ Could not resolve hostname: {host}[/red]")
        return
    
    # Scan options
    console.print("\n[bold]Scan Options:[/bold]")
    console.print("1. Quick scan (common ports)")
    console.print("2. Full scan (ports 1-1024)")
    console.print("3. Custom port range")
    console.print("4. Specific ports")
    
    choice = console.input("\n[cyan]Choose option (1-4): [/cyan]").strip()
    
    if choice == "1":
        scanner.scan_host(host)
    
    elif choice == "2":
        scanner.scan_range(host, 1, 1024)
    
    elif choice == "3":
        start = int(console.input("[cyan]Start port: [/cyan]"))
        end = int(console.input("[cyan]End port: [/cyan]"))
        scanner.scan_range(host, start, end)
    
    elif choice == "4":
        ports_str = console.input("[cyan]Enter ports (comma-separated): [/cyan]")
        ports = [int(p.strip()) for p in ports_str.split(",")]
        scanner.scan_host(host, ports)
    
    else:
        console.print("[red]Invalid choice[/red]")
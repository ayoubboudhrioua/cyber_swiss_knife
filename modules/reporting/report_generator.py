# modules/reporting/report_generator.py

from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
import json

console = Console()

class ReportGenerator:
    """
    Generate comprehensive security reports
    Supports text, HTML, and JSON formats
    """
    
    def __init__(self):
        self.report_dir = Path("reports")
        self.report_dir.mkdir(exist_ok=True)
    
    def create_report(self, scan_type, findings, format='text'):
        """
        Create a security report
        
        Args:
            scan_type: Type of scan (e.g., 'port_scan', 'ssh_audit', 'git_secrets')
            findings: Dictionary of findings
            format: 'text', 'html', or 'json'
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{scan_type}_{timestamp}.{format}"
        filepath = self.report_dir / filename
        
        if format == 'text':
            content = self.generate_text_report(scan_type, findings)
        elif format == 'html':
            content = self.generate_html_report(scan_type, findings)
        elif format == 'json':
            content = self.generate_json_report(scan_type, findings)
        else:
            raise ValueError(f"Unknown format: {format}")
        
        # Write report
        filepath.write_text(content)
        
        return filepath
    
    def generate_text_report(self, scan_type, findings):
        """Generate text format report"""
        
        report = []
        report.append("="*70)
        report.append(f"CYBER SWISS KNIFE - SECURITY REPORT")
        report.append("="*70)
        report.append(f"\nScan Type: {scan_type.replace('_', ' ').title()}")
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("\n" + "="*70)
        report.append("\nEXECUTIVE SUMMARY")
        report.append("="*70)
        
        # Summary based on scan type
        if scan_type == 'port_scan':
            open_ports = findings.get('open_ports', [])
            report.append(f"\nTotal open ports found: {len(open_ports)}")
            report.append(f"Target: {findings.get('target', 'N/A')}")
            report.append(f"Scan duration: {findings.get('duration', 'N/A')}s")
        
        elif scan_type == 'ssh_audit':
            keys = findings.get('keys', [])
            high_risk = sum(1 for k in keys if k.get('risk_score', 0) >= 50)
            report.append(f"\nTotal SSH keys found: {len(keys)}")
            report.append(f"High-risk keys: {high_risk}")
        
        elif scan_type == 'git_secrets':
            secrets = findings.get('secrets', [])
            report.append(f"\nTotal secrets found: {len(secrets)}")
            report.append(f"Unique secret types: {len(set(s.get('type') for s in secrets))}")
        
        # Detailed findings
        report.append("\n" + "="*70)
        report.append("DETAILED FINDINGS")
        report.append("="*70)
        
        for key, value in findings.items():
            if key not in ['target', 'duration']:  # Skip metadata
                report.append(f"\n{key.replace('_', ' ').title()}:")
                
                if isinstance(value, list):
                    for i, item in enumerate(value, 1):
                        if isinstance(item, dict):
                            report.append(f"\n  {i}. " + json.dumps(item, indent=4))
                        else:
                            report.append(f"  {i}. {item}")
                else:
                    report.append(f"  {value}")
        
        # Recommendations
        report.append("\n" + "="*70)
        report.append("RECOMMENDATIONS")
        report.append("="*70)
        report.append(self.get_recommendations(scan_type, findings))
        
        # Footer
        report.append("\n" + "="*70)
        report.append("END OF REPORT")
        report.append("="*70)
        
        return "\n".join(report)
    
    def generate_html_report(self, scan_type, findings):
        """Generate HTML format report"""
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Security Report - {scan_type}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
        }}
        .section {{
            background: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .section h2 {{
            color: #667eea;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }}
        .finding {{
            background: #f8f9fa;
            padding: 15px;
            margin: 10px 0;
            border-left: 4px solid #667eea;
            border-radius: 4px;
        }}
        .high-risk {{
            border-left-color: #dc3545;
            background: #fff5f5;
        }}
        .medium-risk {{
            border-left-color: #ffc107;
            background: #fffbf0;
        }}
        .low-risk {{
            border-left-color: #28a745;
            background: #f0fff4;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }}
        .recommendations {{
            background: #e7f3ff;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #0066cc;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background: #667eea;
            color: white;
        }}
        tr:hover {{
            background: #f5f5f5;
        }}
        .footer {{
            text-align: center;
            color: #666;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔐 Security Report</h1>
        <p><strong>Scan Type:</strong> {scan_type.replace('_', ' ').title()}</p>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="section">
        <h2>📊 Executive Summary</h2>
        {self.generate_html_summary(scan_type, findings)}
    </div>
    
    <div class="section">
        <h2>🔍 Detailed Findings</h2>
        {self.generate_html_findings(scan_type, findings)}
    </div>
    
    <div class="section recommendations">
        <h2>💡 Recommendations</h2>
        {self.get_recommendations(scan_type, findings).replace(chr(10), '<br>')}
    </div>
    
    <div class="footer">
        <p>Generated by Cyber Swiss Knife v2.0</p>
        <p>🔒 Security • 🛡️ Privacy • 🎯 Accuracy</p>
    </div>
</body>
</html>
"""
        return html
    
    def generate_html_summary(self, scan_type, findings):
        """Generate HTML summary section"""
        if scan_type == 'port_scan':
            open_ports = len(findings.get('open_ports', []))
            return f"""
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-number">{open_ports}</div>
                    <div>Open Ports</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{findings.get('duration', 'N/A')}</div>
                    <div>Scan Duration (s)</div>
                </div>
            </div>
            """
        return "<p>Summary data not available</p>"
    
    def generate_html_findings(self, scan_type, findings):
        """Generate HTML findings section"""
        html = ""
        for key, value in findings.items():
            if isinstance(value, list) and value:
                html += f"<h3>{key.replace('_', ' ').title()}</h3>"
                for item in value:
                    html += f'<div class="finding">{json.dumps(item, indent=2)}</div>'
        return html or "<p>No findings to display</p>"
    
    def generate_json_report(self, scan_type, findings):
        """Generate JSON format report"""
        report = {
            'report_metadata': {
                'scan_type': scan_type,
                'generated_at': datetime.now().isoformat(),
                'tool': 'Cyber Swiss Knife v2.0',
            },
            'findings': findings,
            'recommendations': self.get_recommendations(scan_type, findings),
        }
        return json.dumps(report, indent=2)
    
    def get_recommendations(self, scan_type, findings):
        """Get security recommendations based on findings"""
        
        recommendations = {
            'port_scan': """
1. Close unnecessary open ports to reduce attack surface
2. Ensure all services are running latest security patches
3. Use firewall rules to restrict port access
4. Disable services that are not actively used
5. Consider using VPN for administrative access
""",
            'ssh_audit': """
1. Rotate SSH keys older than 1 year
2. Use Ed25519 keys instead of RSA when possible
3. Protect private keys with strong passphrases
4. Set correct file permissions (600) on private keys
5. Remove unused authorized_keys entries
6. Disable password authentication in sshd_config
""",
            'git_secrets': """
1. IMMEDIATELY rotate any exposed credentials
2. Use .gitignore to prevent committing sensitive files
3. Use environment variables or secret managers
4. If secrets already committed, use git-filter-branch or BFG
5. Implement pre-commit hooks to prevent future leaks
6. Review access logs for unauthorized access
""",
        }
        
        return recommendations.get(scan_type, "No specific recommendations available.")
    
    def list_reports(self):
        """List all generated reports"""
        reports = list(self.report_dir.glob("*.*"))
        
        if not reports:
            console.print("[yellow]No reports found[/yellow]")
            return
        
        from rich.table import Table
        table = Table(title="📊 Generated Reports", show_header=True, header_style="bold magenta")
        table.add_column("Filename", style="cyan")
        table.add_column("Size", style="yellow")
        table.add_column("Created", style="green")
        
        for report in sorted(reports, key=lambda x: x.stat().st_mtime, reverse=True):
            size = report.stat().st_size
            created = datetime.fromtimestamp(report.stat().st_mtime).strftime('%Y-%m-%d %H:%M')
            table.add_row(report.name, f"{size:,} bytes", created)
        
        console.print(table)

def run_report_generator():
    """Interactive report generator demo"""
    generator = ReportGenerator()
    
    console.print("\n[bold cyan]📊 Security Report Generator[/bold cyan]\n")
    
    # Menu
    console.print("[bold]Choose option:[/bold]")
    console.print("1. Generate sample port scan report")
    console.print("2. Generate sample SSH audit report")
    console.print("3. List existing reports")
    
    choice = console.input("\n[cyan]Enter choice (1-3): [/cyan]").strip()
    
    if choice == "1":
        # Sample port scan findings
        findings = {
            'target': '192.168.1.100',
            'duration': 12.5,
            'open_ports': [
                {'port': 22, 'service': 'SSH'},
                {'port': 80, 'service': 'HTTP'},
                {'port': 443, 'service': 'HTTPS'},
            ]
        }
        
        format_choice = console.input("[cyan]Format (text/html/json): [/cyan]").strip()
        filepath = generator.create_report('port_scan', findings, format_choice)
        console.print(f"\n[green]✅ Report generated: {filepath}[/green]")
    
    elif choice == "2":
        # Sample SSH audit findings
        findings = {
            'keys': [
                {'name': 'id_rsa', 'type': 'RSA', 'age_days': 400, 'risk_score': 45},
                {'name': 'id_ed25519', 'type': 'Ed25519', 'age_days': 30, 'risk_score': 10},
            ]
        }
        
        format_choice = console.input("[cyan]Format (text/html/json): [/cyan]").strip()
        filepath = generator.create_report('ssh_audit', findings, format_choice)
        console.print(f"\n[green]✅ Report generated: {filepath}[/green]")
    
    elif choice == "3":
        generator.list_reports()
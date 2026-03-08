"""
Config File Auditor — scans .env, .yml, .ini, .cfg, settings.py, etc.
for dangerous misconfigurations, hardcoded secrets, and insecure settings.
"""

import os
import re
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import track

console = Console()


class ConfigAuditor:

    SUPPORTED_EXTENSIONS = {
        ".env", ".yml", ".yaml", ".ini", ".cfg", ".conf",
        ".toml", ".json", ".py", ".properties", ".xml"
    }

    IGNORE_DIRS = {
        ".git", "node_modules", "__pycache__", "venv",
        "myenv", ".venv", "env", "dist", "build"
    }

    RULES = [
        # (name, severity, pattern, description)
        ("Hardcoded Password",      "CRITICAL", r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?[^\s"\'$\{]{4,}',
         "Password value hardcoded in config"),

        ("Hardcoded Secret Key",    "CRITICAL", r'(?i)(secret[_-]?key|secret)\s*[=:]\s*["\']?[^\s"\'$\{]{8,}',
         "Secret key hardcoded — should be an environment variable"),

        ("AWS Credentials",         "CRITICAL", r'(?i)(aws_access_key|aws_secret)\s*[=:]\s*[A-Za-z0-9/+=]{16,}',
         "AWS credentials found in config file"),

        ("Debug Mode Enabled",      "HIGH",     r'(?i)(DEBUG|debug)\s*[=:]\s*(True|true|1|yes|on)',
         "Debug mode should be disabled in production"),

        ("Weak Secret Key",         "HIGH",     r'(?i)secret[_-]?key\s*[=:]\s*["\']?(changeme|secret|default|dev|test|insecure|replace)',
         "Secret key is a placeholder value"),

        ("Localhost Binding",       "MEDIUM",   r'(?i)(HOST|BIND|listen)\s*[=:]\s*["\']?0\.0\.0\.0',
         "Service bound to all interfaces — restrict in production"),

        ("HTTP instead of HTTPS",   "MEDIUM",   r'(?i)(url|endpoint|host)\s*[=:]\s*["\']?http://(?!localhost|127)',
         "Non-localhost HTTP URL — consider HTTPS"),

        ("Plaintext Database URL",  "HIGH",     r'(?i)(DATABASE_URL|DB_URL)\s*[=:]\s*["\']?[a-z]+://[^$\{][^\s]+',
         "Database URL with credentials in plaintext"),

        ("Weak Encryption Setting", "MEDIUM",   r'(?i)(algorithm|cipher|hash)\s*[=:]\s*["\']?(md5|sha1|des|rc4)',
         "Weak cryptographic algorithm configured"),

        ("Allowed Hosts Wildcard",  "MEDIUM",   r'(?i)allowed_hosts\s*[=:]\s*[\["\']?\s*\*',
         "ALLOWED_HOSTS set to wildcard — dangerous in production"),

        ("Disabled CSRF",           "HIGH",     r'(?i)(csrf|CSRF).*(false|disabled|False|0)',
         "CSRF protection appears disabled"),

        ("Disabled SSL Verify",     "HIGH",     r'(?i)(verify|SSL_VERIFY|VERIFY_SSL)\s*[=:]\s*(false|False|0|no)',
         "SSL certificate verification disabled"),

        ("Default Admin Creds",     "CRITICAL", r'(?i)(admin|root|superuser).*(password|passwd)\s*[=:]\s*["\']?(admin|root|password|123)',
         "Default admin credentials detected"),

        ("Exposed Internal IP",     "LOW",      r'\b(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.1[6-9]\.\d+|172\.2\d\.\d+|172\.3[01]\.\d+)\b',
         "Internal IP address hardcoded"),
    ]

    def scan_file(self, file_path: Path) -> list[dict]:
        """Scan a single file for misconfigurations."""
        findings = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()

            for line_num, line in enumerate(lines, 1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue  # skip comments and blank lines

                for rule_name, severity, pattern, description in self.RULES:
                    if re.search(pattern, line):
                        findings.append({
                            "file": str(file_path),
                            "line": line_num,
                            "rule": rule_name,
                            "severity": severity,
                            "description": description,
                            "content": stripped[:120],
                        })
                        break  # one finding per line

        except Exception:
            pass
        return findings

    def scan_directory(self, directory: str) -> list[dict]:
        """Recursively scan directory for config issues."""
        base = Path(directory)
        all_findings = []

        config_files = []
        for root, dirs, files in os.walk(base):
            dirs[:] = [d for d in dirs if d not in self.IGNORE_DIRS]
            for f in files:
                fp = Path(root) / f
                if fp.suffix in self.SUPPORTED_EXTENSIONS or fp.name.startswith(".env"):
                    config_files.append(fp)

        for fp in track(config_files, description="Scanning config files..."):
            all_findings.extend(self.scan_file(fp))

        return all_findings

    def display_findings(self, findings: list[dict]) -> None:
        SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        SEVERITY_COLOR = {
            "CRITICAL": "[bold red]",
            "HIGH":     "[red]",
            "MEDIUM":   "[yellow]",
            "LOW":      "[cyan]",
        }

        if not findings:
            console.print(Panel(
                "[bold green]✅ No misconfigurations detected![/bold green]\n"
                "[dim]Your config files look clean.[/dim]",
                border_style="green"
            ))
            return

        findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 9))

        # Summary
        by_sev = {}
        for f in findings:
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1

        summary = "  ".join(
            f"{SEVERITY_COLOR[s]}{s}: {n}[/]"
            for s, n in sorted(by_sev.items(), key=lambda x: SEVERITY_ORDER.get(x[0], 9))
        )
        console.print(Panel(
            f"[bold red]⚠️  Found {len(findings)} configuration issue(s)[/bold red]\n{summary}",
            border_style="red"
        ))

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Severity", width=10)
        table.add_column("File", width=25)
        table.add_column("Line", width=5, justify="right")
        table.add_column("Rule", width=25)
        table.add_column("Detail", width=40)

        for f in findings:
            color = SEVERITY_COLOR[f["severity"]]
            table.add_row(
                f"{color}{f['severity']}[/]",
                Path(f["file"]).name,
                str(f["line"]),
                f["rule"],
                f["description"],
            )
        console.print(table)

        console.print("\n[bold cyan]🛡️  Remediation Guide:[/bold cyan]")
        console.print("  1. Move all secrets to environment variables or a secrets manager")
        console.print("  2. Never commit .env files — add to .gitignore")
        console.print("  3. Use python-decouple or dotenv to load config safely")
        console.print("  4. Set DEBUG=False and restrict ALLOWED_HOSTS in production")
        console.print("  5. Always use HTTPS endpoints and verify SSL certificates")
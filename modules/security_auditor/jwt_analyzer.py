"""Jwt Analyzer - Decode , validate and audit JSON Web tokens
Detects alg:none attacks, weak algorithms;expiry issues suspicious claims"""
import base64
import json
import hmac
import hashlib
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.syntax import Syntax
from rich.panel import Panel

console = Console()

class JWTAnalyzer:
    WEAK_ALGORITHMS = {"none", "HS256"}  # HS256 weak if secret is guessable
    DANGEROUS_ALGORITHMS = {"none"}
    COMMON_SECRETS = [
        "secret", "password", "123456", "qwerty", "changeme",
        "your-256-bit-secret", "jwt_secret", "mysecret", "key",
        "supersecret", "admin", "test", "demo", "example"
    ]

    def decode_jwt(self, token: str) -> dict:
        """Decode a JWT without verifying signature — analysis only."""
        result = {
            "raw": token,
            "header": None,
            "payload": None,
            "signature": None,
            "issues": [],
            "risk_score": 0,
            "valid_structure": False,
        }

        parts = token.strip().split(".")
        if len(parts) != 3:
            result["issues"].append("Invalid JWT structure — must have 3 parts separated by dots")
            return result

        result["valid_structure"] = True

        try:
            result["header"] = self._decode_part(parts[0])
        except Exception as e:
            result["issues"].append(f"Could not decode header: {e}")
            return result

        try:
            result["payload"] = self._decode_part(parts[1])
        except Exception as e:
            result["issues"].append(f"Could not decode payload: {e}")
            return result

        result["signature"] = parts[2]
        return result

    def _decode_part(self, part: str) -> dict:
        """Base64url decode a JWT part."""
        padding = 4 - len(part) % 4
        if padding != 4:
            part += "=" * padding
        decoded = base64.urlsafe_b64decode(part)
        return json.loads(decoded)

    def analyze(self, token: str) -> dict:
        """Full security analysis of a JWT."""
        result = self.decode_jwt(token)
        if not result["valid_structure"]:
            return result

        header = result["header"]
        payload = result["payload"]
        issues = result["issues"]

        # --- Algorithm checks ---
        alg = header.get("alg", "").upper()

        if alg == "NONE" or header.get("alg", "") == "none":
            issues.append("CRITICAL: Algorithm is 'none' — signature is not verified. Classic JWT attack vector.")
            result["risk_score"] += 100

        elif alg in {"HS256", "HS384", "HS512"}:
            issues.append(f"WARNING: {alg} uses a symmetric secret. If the secret is weak, the token can be forged.")
            result["risk_score"] += 20
            # Try common secrets
            cracked = self._try_crack_hs(token, alg)
            if cracked:
                issues.append(f"CRITICAL: Secret cracked! The signing secret is: '{cracked}'")
                result["risk_score"] += 80
                result["cracked_secret"] = cracked

        elif alg in {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}:
            issues.append(f"INFO: {alg} uses asymmetric signing — good choice.")

        else:
            issues.append(f"WARNING: Unknown algorithm '{alg}'")
            result["risk_score"] += 30

        # --- Expiry checks ---
        now = datetime.utcnow().timestamp()

        if "exp" not in payload:
            issues.append("WARNING: No expiration (exp) claim — token never expires.")
            result["risk_score"] += 25
        else:
            exp = payload["exp"]
            exp_dt = datetime.utcfromtimestamp(exp)
            if exp < now:
                issues.append(f"INFO: Token expired on {exp_dt.strftime('%Y-%m-%d %H:%M:%S')} UTC")
            else:
                days_left = (exp_dt - datetime.utcnow()).days
                if days_left > 365:
                    issues.append(f"WARNING: Token expires in {days_left} days — suspiciously long-lived.")
                    result["risk_score"] += 15

        if "iat" not in payload:
            issues.append("INFO: No issued-at (iat) claim — cannot verify token age.")

        if "nbf" in payload and payload["nbf"] > now:
            issues.append("INFO: Token not yet valid (nbf claim is in the future).")

        # --- Sensitive data in payload ---
        sensitive_keys = {"password", "passwd", "pwd", "secret", "token",
                          "credit_card", "ssn", "cvv", "pin"}
        found_sensitive = [k for k in payload if k.lower() in sensitive_keys]
        if found_sensitive:
            issues.append(f"CRITICAL: Sensitive fields in payload (not encrypted!): {found_sensitive}")
            result["risk_score"] += 40

        # --- Audience / Issuer ---
        if "aud" not in payload:
            issues.append("INFO: No audience (aud) claim — token can be replayed against any service.")
        if "iss" not in payload:
            issues.append("INFO: No issuer (iss) claim.")

        result["risk_score"] = min(result["risk_score"], 100)
        return result

    def _try_crack_hs(self, token: str, alg: str) -> str | None:
        """Attempt to crack HMAC secret using common passwords."""
        hash_map = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }
        hash_fn = hash_map.get(alg, hashlib.sha256)
        parts = token.strip().split(".")
        message = f"{parts[0]}.{parts[1]}".encode()
        sig_padded = parts[2] + "=" * (4 - len(parts[2]) % 4)
        try:
            expected_sig = base64.urlsafe_b64decode(sig_padded)
        except Exception:
            return None

        for secret in self.COMMON_SECRETS:
            computed = hmac.new(secret.encode(), message, hash_fn).digest()
            if hmac.compare_digest(computed, expected_sig):
                return secret
        return None

    def display_analysis(self, result: dict):
        """Render full JWT analysis with Rich."""
        if not result["valid_structure"]:
            console.print(Panel(
                f"[red]❌ {result['issues'][0]}[/red]",
                title="JWT Analysis Failed", border_style="red"
            ))
            return

        # Risk level
        score = result["risk_score"]
        if score == 0:
            risk_label = "[green]LOW[/green] ✅"
        elif score < 40:
            risk_label = "[yellow]MEDIUM[/yellow] ⚠️"
        else:
            risk_label = "[red]HIGH[/red] 🚨"

        # Header + Payload display
        console.print("\n[bold cyan]── Header ──────────────────────────────[/bold cyan]")
        console.print(Syntax(
            json.dumps(result["header"], indent=2),
            "json", theme="monokai", line_numbers=False
        ))

        console.print("\n[bold cyan]── Payload ─────────────────────────────[/bold cyan]")
        payload_display = dict(result["payload"])
        # Convert timestamps to human readable
        for key in ("exp", "iat", "nbf"):
            if key in payload_display:
                try:
                    dt = datetime.utcfromtimestamp(payload_display[key])
                    payload_display[key] = f"{payload_display[key]} ({dt.strftime('%Y-%m-%d %H:%M:%S')} UTC)"
                except Exception:
                    pass
        console.print(Syntax(
            json.dumps(payload_display, indent=2),
            "json", theme="monokai", line_numbers=False
        ))

        # Issues table
        console.print("\n[bold cyan]── Security Findings ───────────────────[/bold cyan]")
        table = Table(show_header=True, header_style="bold magenta", box=None)
        table.add_column("Severity", width=12)
        table.add_column("Finding")

        for issue in result["issues"]:
            if issue.startswith("CRITICAL"):
                table.add_row("[bold red]CRITICAL[/bold red]", issue.replace("CRITICAL: ", ""))
            elif issue.startswith("WARNING"):
                table.add_row("[yellow]WARNING[/yellow]", issue.replace("WARNING: ", ""))
            else:
                table.add_row("[cyan]INFO[/cyan]", issue.replace("INFO: ", ""))

        console.print(table)

        console.print(Panel(
            f"[bold]Risk Score:[/bold] {score}/100   [bold]Risk Level:[/bold] {risk_label}",
            border_style="cyan"
        ))


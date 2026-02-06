from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import re
console = Console()
class PasswordPolicy:
    """
    Password policy validator and explainer
    Helps users understand why their passwords are weak
    """
    def __init__(self):
        # Define common password policies
        self.policies = {
            'nist_basic': {
                'name': 'NIST Basic (Recommended)',
                'min_length': 8,
                'max_length': 64,
                'require_uppercase': False,
                'require_lowercase': False,
                'require_digits': False,
                'require_special': False,
                'block_common': True,
                'block_sequential': True,
                'description': 'Modern NIST guidelines focus on length over complexity'
            },
            'corporate_standard': {
                'name': 'Corporate Standard',
                'min_length': 12,
                'max_length': 128,
                'require_uppercase': True,
                'require_lowercase': True,
                'require_digits': True,
                'require_special': True,
                'block_common': True,
                'block_sequential': True,
                'description': 'Typical enterprise password policy'
            },
            'high_security': {
                'name': 'High Security',
                'min_length': 16,
                'max_length': 256,
                'require_uppercase': True,
                'require_lowercase': True,
                'require_digits': True,
                'require_special': True,
                'block_common': True,
                'block_sequential': True,
                'block_personal': True,
                'description': 'For critical systems and privileged accounts'
            },
            'legacy_windows': {
                'name': 'Legacy Windows',
                'min_length': 8,
                'max_length': 14,
                'require_uppercase': True,
                'require_lowercase': True,
                'require_digits': True,
                'require_special': False,
                'block_common': False,
                'block_sequential': False,
                'description': 'Old Windows password requirements (NOT recommended)'
            }
        }
    
    def validate_against_policy(self, password, policy_name='nist_basic'):
        """
        Validate password against a specific policy
        Returns: (is_valid, violations, recommendations)
        """
        if policy_name not in self.policies:
            return False, ["Invalid policy name"], []
        
        policy = self.policies[policy_name]
        violations = []
        recommendations = []
        
        # Length check
        if len(password) < policy['min_length']:
            violations.append(f"Too short (minimum {policy['min_length']} characters)")
            recommendations.append(f"Add at least {policy['min_length'] - len(password)} more characters")
        
        if len(password) > policy['max_length']:
            violations.append(f"Too long (maximum {policy['max_length']} characters)")
        
        # Character requirements
        if policy.get('require_uppercase', False):
            if not re.search(r'[A-Z]', password):
                violations.append("Missing uppercase letter")
                recommendations.append("Add at least one uppercase letter (A-Z)")
        
        if policy.get('require_lowercase', False):
            if not re.search(r'[a-z]', password):
                violations.append("Missing lowercase letter")
                recommendations.append("Add at least one lowercase letter (a-z)")
        
        if policy.get('require_digits', False):
            if not re.search(r'\d', password):
                violations.append("Missing digit")
                recommendations.append("Add at least one number (0-9)")
        
        if policy.get('require_special', False):
            if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
                violations.append("Missing special character")
                recommendations.append("Add at least one special character (!@#$%^&*)")
        
        # Common password check
        if policy.get('block_common', False):
            if self.is_common_password(password):
                violations.append("Password appears in common password lists")
                recommendations.append("Choose a unique password not found in dictionaries")
        
        # Sequential characters check
        if policy.get('block_sequential', False):
            if self.has_sequential_chars(password):
                violations.append("Contains sequential characters (e.g., 'abc', '123')")
                recommendations.append("Avoid sequential patterns like abc, 123, qwerty")
        
        is_valid = len(violations) == 0
        
        return is_valid, violations, recommendations
    
    def is_common_password(self, password):
        """Check if password is in common passwords list"""
        common = [
            'password', 'password123', '123456', '12345678', 'qwerty',
            'abc123', 'monkey', 'letmein', 'trustno1', 'dragon',
            'baseball', '111111', 'iloveyou', 'master', 'sunshine',
            'ashley', 'bailey', 'passw0rd', 'shadow', '123123'
        ]
        return password.lower() in common
    
    def has_sequential_chars(self, password):
        """Check for sequential characters"""
        sequences = ['abc', '123', 'qwe', 'asd', 'zxc']
        password_lower = password.lower()
        
        # Check known sequences
        for seq in sequences:
            if seq in password_lower:
                return True
        
        # Check for 3+ sequential numbers
        for i in range(len(password) - 2):
            if password[i:i+3].isdigit():
                nums = [int(password[i+j]) for j in range(3)]
                if nums[1] == nums[0] + 1 and nums[2] == nums[1] + 1:
                    return True
        
        return False
    
    def compare_policies(self, password):
        """
        Compare password against all policies
        """
        console.print(f"\n[bold cyan]🔒 Password Policy Comparison[/bold cyan]")
        console.print(f"[dim]Testing password against different policies...[/dim]\n")
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Policy", style="cyan", width=20)
        table.add_column("Status", style="yellow", width=10)
        table.add_column("Violations", style="red")
        
        for policy_name, policy_info in self.policies.items():
            is_valid, violations, _ = self.validate_against_policy(password, policy_name)
            
            status = "✅ PASS" if is_valid else "❌ FAIL"
            violations_str = "\n".join(violations) if violations else "None"
            
            table.add_row(
                policy_info['name'],
                status,
                violations_str
            )
        
        console.print(table)
    
    def explain_policy(self, policy_name='nist_basic'):
        """Explain a specific password policy"""
        
        if policy_name not in self.policies:
            console.print("[red]Invalid policy name[/red]")
            return
        
        policy = self.policies[policy_name]
        
        explanation = f"""
[bold]{policy['name']}[/bold]

[yellow]Description:[/yellow]
{policy['description']}

[yellow]Requirements:[/yellow]
- Length: {policy['min_length']}-{policy['max_length']} characters
- Uppercase: {'Required' if policy.get('require_uppercase') else 'Optional'}
- Lowercase: {'Required' if policy.get('require_lowercase') else 'Optional'}
- Digits: {'Required' if policy.get('require_digits') else 'Optional'}
- Special characters: {'Required' if policy.get('require_special') else 'Optional'}
- Block common passwords: {'Yes' if policy.get('block_common') else 'No'}
- Block sequential patterns: {'Yes' if policy.get('block_sequential') else 'No'}

[yellow]Why this matters:[/yellow]
"""
        
        # Add security explanation
        if policy_name == 'nist_basic':
            explanation += """
NIST now recommends LENGTH over complexity. A long passphrase like
"correct-horse-battery-staple" is stronger than "P@ssw0rd1!" because:
  • Longer passwords are exponentially harder to crack
  • Easier to remember means users won't write them down
  • No forced complexity means fewer predictable patterns
"""
        elif policy_name == 'corporate_standard':
            explanation += """
Enterprise environments balance security with usability:
  • Mix of requirements catches most weak passwords
  • 12+ characters provides good protection
  • Complexity prevents simple dictionary attacks
"""
        
        console.print(Panel(explanation, border_style="cyan"))

def run_password_policy():
    """Interactive password policy validator"""
    validator = PasswordPolicy()
    
    console.print("\n[bold cyan]🔒 Password Policy Validator[/bold cyan]\n")
    
    # Menu
    console.print("[bold]Choose option:[/bold]")
    console.print("1. Test password against all policies")
    console.print("2. Validate against specific policy")
    console.print("3. Explain a policy")
    console.print("4. List all policies")
    
    choice = console.input("\n[cyan]Enter choice (1-4): [/cyan]").strip()
    
    if choice == "1":
        password = console.input("\n[cyan]Enter password to test: [/cyan]")
        validator.compare_policies(password)
    
    elif choice == "2":
        console.print("\n[bold]Available policies:[/bold]")
        for name, policy in validator.policies.items():
            console.print(f"  • {name}: {policy['name']}")
        
        policy_name = console.input("\n[cyan]Enter policy name: [/cyan]").strip()
        password = console.input("[cyan]Enter password: [/cyan]")
        
        is_valid, violations, recommendations = validator.validate_against_policy(
            password, policy_name
        )
        
        if is_valid:
            console.print("\n[green]✅ Password meets policy requirements![/green]")
        else:
            console.print("\n[red]❌ Password does not meet policy requirements[/red]\n")
            console.print("[bold]Violations:[/bold]")
            for v in violations:
                console.print(f"  • {v}")
            
            if recommendations:
                console.print("\n[bold yellow]Recommendations:[/bold yellow]")
                for r in recommendations:
                    console.print(f"  • {r}")
    
    elif choice == "3":
        console.print("\n[bold]Available policies:[/bold]")
        for name, policy in validator.policies.items():
            console.print(f"  • {name}: {policy['name']}")
        
        policy_name = console.input("\n[cyan]Enter policy name: [/cyan]").strip()
        validator.explain_policy(policy_name)
    
    elif choice == "4":
        table = Table(title="Password Policies", show_header=True, header_style="bold magenta")
        table.add_column("Code", style="cyan", width=20)
        table.add_column("Name", style="yellow", width=25)
        table.add_column("Description", style="white")
        
        for code, policy in validator.policies.items():
            table.add_row(code, policy['name'], policy['description'])
        
        console.print("\n", table)
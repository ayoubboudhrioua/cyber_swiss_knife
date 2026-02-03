import re
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

class PhishingDetector:
    """Analyze emails for phishing indicators"""
    
    def __init__(self):
        self.suspicious_keywords = [
            'urgent', 'verify', 'suspended', 'unusual activity',
            'confirm your account', 'click here immediately',
            'reset your password', 'unusual sign-in',
            'expires today', 'act now', 'limited time',
            'congratulations', 'you won', 'claim your prize'
        ]
        
        self.suspicious_domains = [
            'tk', 'ml', 'ga', 'cf', 'gq'  # Common free TLDs used in phishing
        ]
    
    def analyze_email(self, email_text, sender_email, subject):
        """
        Analyze email for phishing indicators
        Returns: (risk_score: int, indicators: list)
        """
        indicators = []
        risk_score = 0
        
        # 1. Check sender email domain
        sender_risk, sender_indicators = self._check_sender(sender_email)
        risk_score += sender_risk
        indicators.extend(sender_indicators)
        
        # 2. Check for suspicious keywords
        keyword_risk, keyword_indicators = self._check_keywords(email_text, subject)
        risk_score += keyword_risk
        indicators.extend(keyword_indicators)
        
        # 3. Check URLs
        url_risk, url_indicators = self._check_urls(email_text)
        risk_score += url_risk
        indicators.extend(url_indicators)
        
        # 4. Check for urgency tactics
        urgency_risk, urgency_indicators = self._check_urgency(email_text, subject)
        risk_score += urgency_risk
        indicators.extend(urgency_indicators)
        
        # 5. Check for spoofing attempts
        spoof_risk, spoof_indicators = self._check_spoofing(sender_email, email_text)
        risk_score += spoof_risk
        indicators.extend(spoof_indicators)
        
        return risk_score, indicators
    
    def _check_sender(self, sender_email):
        """Check if sender email looks suspicious"""
        indicators = []
        risk = 0
        
        try:
            domain = sender_email.split('@')[1]
            tld = domain.split('.')[-1]
            
            # Check for suspicious TLDs
            if tld in self.suspicious_domains:
                indicators.append(f"Suspicious domain extension: .{tld}")
                risk += 15
            
            # Check for lookalike domains
            common_brands = ['paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook']
            for brand in common_brands:
                if brand in domain.lower() and brand not in domain.split('.')[0]:
                    indicators.append(f"Possible spoofed domain resembling {brand}")
                    risk += 25
            
            # Check for excessive subdomains
            if domain.count('.') > 2:
                indicators.append("Excessive subdomains (potential obfuscation)")
                risk += 10
                
        except IndexError:
            indicators.append("Invalid email format")
            risk += 20
        
        return risk, indicators
    
    def _check_keywords(self, email_text, subject):
        """Check for suspicious phishing keywords"""
        indicators = []
        risk = 0
        
        text_lower = (email_text + " " + subject).lower()
        
        found_keywords = []
        for keyword in self.suspicious_keywords:
            if keyword in text_lower:
                found_keywords.append(keyword)
        
        if found_keywords:
            indicators.append(f"Suspicious keywords found: {', '.join(found_keywords[:3])}")
            risk += len(found_keywords) * 5
        
        return risk, indicators
    
    def _check_urls(self, email_text):
        """Extract and analyze URLs"""
        indicators = []
        risk = 0
        
        # Find all URLs
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, email_text)
        
        for url in urls:
            parsed = urlparse(url)
            
            # Check for IP addresses instead of domains
            if re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc):
                indicators.append(f"URL uses IP address instead of domain: {url}")
                risk += 20
            
            # Check for URL shorteners
            shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co']
            if any(short in parsed.netloc for short in shorteners):
                indicators.append(f"URL shortener detected: {parsed.netloc}")
                risk += 10
            
            # Check for misleading links
            if '@' in url:
                indicators.append(f"URL contains @ symbol (potential redirect): {url}")
                risk += 25
        
        if len(urls) > 5:
            indicators.append(f"Excessive number of links: {len(urls)}")
            risk += 10
        
        return risk, indicators
    
    def _check_urgency(self, email_text, subject):
        """Check for urgency/pressure tactics"""
        indicators = []
        risk = 0
        
        urgency_patterns = [
            r'within (\d+) (hours?|days?|minutes?)',
            r'expires? (today|tonight|soon|immediately)',
            r'act now',
            r'limited time',
            r'urgent',
            r'immediate action required'
        ]
        
        text_lower = (email_text + " " + subject).lower()
        
        for pattern in urgency_patterns:
            if re.search(pattern, text_lower):
                indicators.append(f"Urgency tactic detected: '{pattern}'")
                risk += 10
                break  # Only count once
        
        return risk, indicators
    
    def _check_spoofing(self, sender_email, email_text):
        """Check for display name spoofing"""
        indicators = []
        risk = 0
        
        # Check if display name is mentioned in email
        # This is a simplified check
        common_services = ['PayPal', 'Amazon', 'Apple', 'Microsoft', 'Google', 'Bank']
        
        for service in common_services:
            if service.lower() in email_text.lower():
                if service.lower() not in sender_email.lower():
                    indicators.append(f"Email mentions {service} but sender domain doesn't match")
                    risk += 20
        
        return risk, indicators
    
    def display_analysis(self, risk_score, indicators, sender_email, subject):
        """Display beautiful analysis results"""
        
        # Determine risk level
        if risk_score < 20:
            risk_level = "[green]LOW[/green]"
            risk_emoji = "✅"
        elif risk_score < 50:
            risk_level = "[yellow]MEDIUM[/yellow]"
            risk_emoji = "⚠️"
        else:
            risk_level = "[red]HIGH[/red]"
            risk_emoji = "🚨"
        
        # Create summary panel
        summary = f"""
[bold]From:[/bold] {sender_email}
[bold]Subject:[/bold] {subject}

[bold]Risk Score:[/bold] {risk_score}/100
[bold]Risk Level:[/bold] {risk_level} {risk_emoji}
        """
        
        console.print(Panel(summary, title="📧 Email Analysis", border_style="cyan"))
        
        # Display indicators
        if indicators:
            console.print("\n[bold red]⚠️  Phishing Indicators Detected:[/bold red]\n")
            for i, indicator in enumerate(indicators, 1):
                console.print(f"  {i}. {indicator}")
        else:
            console.print("\n[green]✅ No obvious phishing indicators detected[/green]")
        
        # Recommendations
        console.print("\n[bold cyan]🛡️  Security Recommendations:[/bold cyan]")
        if risk_score >= 50:
            console.print("  • [red]HIGH RISK - Do NOT click any links or attachments[/red]")
            console.print("  • Delete this email immediately")
            console.print("  • Report to your IT department")
        elif risk_score >= 20:
            console.print("  • [yellow]Exercise caution with this email[/yellow]")
            console.print("  • Verify sender through alternative means")
            console.print("  • Don't click links - visit sites directly")
        else:
            console.print("  • [green]Email appears relatively safe[/green]")
            console.print("  • Still verify sender if unexpected")

# Usage example
def analyze_sample_phishing():
    detector = PhishingDetector()
    
    # Sample phishing email
    sender = "security@paypa1-verify.tk"
    subject = "URGENT: Verify your account within 24 hours"
    email_body = """
    Dear PayPal Customer,
    
    We have detected unusual activity on your account.
    Please verify your identity immediately by clicking here:
    http://192.168.1.1/paypal-verify.php?user=12345
    
    Your account will be suspended if you don't act within 24 hours.
    
    Thank you,
    PayPal Security Team
    """
    
    risk_score, indicators = detector.analyze_email(email_body, sender, subject)
    detector.display_analysis(risk_score, indicators, sender, subject)
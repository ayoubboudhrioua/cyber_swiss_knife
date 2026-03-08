import pytest
from modules.attack_tools.phishing_detector import PhishingDetector

@pytest.fixture
def detector():
    return PhishingDetector()

def test_obvious_phishing_gets_high_score(detector):
    score, indicators = detector.analyze_email(
        "Dear PayPal Customer, unusual activity detected. Click here immediately: http://192.168.1.1/verify or your account will be suspended within 24 hours.",
        "security@paypa1-verify.tk",
        "URGENT: Verify your account now"
    )
    assert score >= 50
    assert len(indicators) > 0

def test_clean_email_gets_low_score(detector):
    score, indicators = detector.analyze_email(
        "Hi team, the meeting is at 3pm tomorrow.",
        "colleague@company.com",
        "Meeting reminder"
    )
    assert score < 20

def test_ip_url_flagged(detector):
    _, indicators = detector.analyze_email(
        "Visit http://192.168.1.1/login",
        "test@example.com",
        "Hello"
    )
    assert any("IP" in i or "ip" in i.lower() for i in indicators)

def test_suspicious_tld_flagged(detector):
    _, indicators = detector.analyze_email(
        "Normal message",
        "admin@something.tk",
        "Hello"
    )
    assert any("tk" in i for i in indicators)

def test_brand_spoofing_flagged(detector):
    _, indicators = detector.analyze_email(
        "Your PayPal account needs verification.",
        "noreply@scammer.com",
        "PayPal Notice"
    )
    assert any("PayPal" in i or "paypal" in i.lower() for i in indicators)
import pytest
from modules.security_auditor.jwt_analyzer import JWTAnalyzer
import base64, json, hmac, hashlib

def make_jwt(header, payload, secret="secret"):
    def b64(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    h, p = b64(header), b64(payload)
    msg = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
    return f"{h}.{p}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"

@pytest.fixture
def analyzer(): return JWTAnalyzer()

def test_invalid_structure(analyzer):
    r = analyzer.analyze("notajwt")
    assert not r["valid_structure"]

def test_decode_valid_jwt(analyzer):
    token = make_jwt({"alg":"HS256","typ":"JWT"}, {"sub":"1","name":"test"})
    r = analyzer.analyze(token)
    assert r["valid_structure"]
    assert r["payload"]["sub"] == "1"

def test_no_expiry_flagged(analyzer):
    token = make_jwt({"alg":"HS256","typ":"JWT"}, {"sub":"1"})
    r = analyzer.analyze(token)
    assert any("expir" in i.lower() for i in r["issues"])

def test_weak_secret_cracked(analyzer):
    token = make_jwt({"alg":"HS256","typ":"JWT"}, {"sub":"1"}, secret="secret")
    r = analyzer.analyze(token)
    assert r.get("cracked_secret") == "secret"

def test_sensitive_payload_flagged(analyzer):
    token = make_jwt({"alg":"HS256","typ":"JWT"}, {"password":"hunter2"}, secret="x")
    r = analyzer.analyze(token)
    assert any("sensitive" in i.lower() for i in r["issues"])
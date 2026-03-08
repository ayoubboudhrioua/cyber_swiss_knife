import pytest
from modules.password.passwords import check_strength, hash_pw, verify_password

def test_weak_password_flagged():
    result = check_strength("123456")
    assert result.startswith("Weak")

def test_strong_password_accepted():
    result = check_strength("correct-horse-battery-staple-99!")
    assert result.startswith("Strong") or result.startswith("Very strong")

def test_hash_pw_returns_bytes():
    hashed = hash_pw("testpassword")
    assert isinstance(hashed, bytes)

def test_hash_pw_different_salts():
    h1 = hash_pw("samepassword")
    h2 = hash_pw("samepassword")
    assert h1 != h2  # bcrypt salts should differ

def test_verify_password_correct():
    hashed = hash_pw("mypassword")
    result = verify_password("mypassword", hashed)
    assert "granted" in result.lower()

def test_verify_password_incorrect():
    hashed = hash_pw("mypassword")
    result = verify_password("wrongpassword", hashed)
    assert "denied" in result.lower()
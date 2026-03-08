import pytest
from modules.password.password_policy import PasswordPolicy

@pytest.fixture
def policy():
    return PasswordPolicy()

def test_short_password_fails_nist(policy):
    valid, violations, _ = policy.validate_against_policy("hi", "nist_basic")
    assert not valid
    assert any("short" in v.lower() for v in violations)

def test_good_passphrase_passes_nist(policy):
    valid, violations, _ = policy.validate_against_policy(
        "correct-horse-battery-staple", "nist_basic"
    )
    assert valid

def test_corporate_requires_uppercase(policy):
    valid, violations, _ = policy.validate_against_policy(
        "nouppercase1!", "corporate_standard"
    )
    assert any("uppercase" in v.lower() for v in violations)

def test_corporate_requires_special(policy):
    valid, violations, _ = policy.validate_against_policy(
        "NoSpecialChar1", "corporate_standard"
    )
    assert any("special" in v.lower() for v in violations)

def test_common_password_blocked(policy):
    assert policy.is_common_password("password") is True
    assert policy.is_common_password("xK9#mQ2!vL") is False

def test_sequential_chars_detected(policy):
    assert policy.has_sequential_chars("abc123") is True
    assert policy.has_sequential_chars("xK9mQ2vL") is False
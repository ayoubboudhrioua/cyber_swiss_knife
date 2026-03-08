import pytest, string
from modules.password.password_generator import PasswordGenerator

@pytest.fixture
def gen(): return PasswordGenerator()

def test_length_respected(gen):
    for length in [8, 16, 24, 32]:
        assert len(gen.generate_random(length)) == length

def test_symbols_included(gen):
    results = [gen.generate_random(20, use_symbols=True) for _ in range(20)]
    assert any(any(c in "!@#$%^&*-_=+?" for c in r) for r in results)

def test_no_ambiguous_chars(gen):
    ambiguous = set("lI0O")
    for _ in range(50):
        pwd = gen.generate_random(20, exclude_ambiguous=True)
        assert not ambiguous.intersection(set(pwd))

def test_passphrase_word_count(gen):
    for n in [3, 4, 5]:
        phrase = gen.generate_passphrase(n, separator="-", add_number=False)
        assert len(phrase.split("-")) == n

def test_pin_numeric(gen):
    pin = gen.generate_pin(6)
    assert pin.isdigit() and len(pin) == 6

def test_entropy_positive(gen):
    assert gen.calculate_entropy("Tr0ub4dor&3") > 0

def test_uniqueness(gen):
    pwds = {gen.generate_random(16) for _ in range(20)}
    assert len(pwds) == 20  # all unique
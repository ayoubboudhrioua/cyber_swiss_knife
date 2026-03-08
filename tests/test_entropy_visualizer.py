import pytest
from modules.password.entropy_visualizer import EntropyVisualizer

@pytest.fixture
def ev(): return EntropyVisualizer()

def test_empty_password_zero_entropy(ev):
    stats = ev.calculate_entropy("")
    assert stats["entropy_bits"] == 0

def test_longer_password_higher_entropy(ev):
    short = ev.calculate_entropy("abc")
    long  = ev.calculate_entropy("abcdefghijklmnop")
    assert long["entropy_bits"] > short["entropy_bits"]

def test_mixed_charset_higher_entropy(ev):
    lower  = ev.calculate_entropy("abcdefgh")
    mixed  = ev.calculate_entropy("Abcde1!X")
    assert mixed["entropy_bits"] > lower["entropy_bits"]

def test_crack_time_returns_all_scenarios(ev):
    times = ev.estimate_crack_time(60.0)
    assert len(times) == 5

def test_charset_detection(ev):
    stats = ev.calculate_entropy("Hello1!")
    assert stats["charset"]["lowercase"]
    assert stats["charset"]["uppercase"]
    assert stats["charset"]["digits"]
    assert stats["charset"]["symbols"]

def test_shannon_entropy_positive(ev):
    stats = ev.calculate_entropy("password")
    assert stats["shannon"] > 0
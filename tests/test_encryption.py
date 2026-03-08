import pytest
from modules.encryption.encryption import aes_ed, rsa_ed

def test_aes_roundtrip():
    message = "Hello, World!"
    key, ciphertext, plaintext = aes_ed(message)
    assert plaintext == message

def test_aes_key_is_hex_string():
    key, _, _ = aes_ed("test")
    assert len(key) == 64  # 32 bytes as hex

def test_aes_ciphertext_differs_from_plaintext():
    message = "secret"
    _, ciphertext, _ = aes_ed(message)
    assert message not in ciphertext

def test_aes_different_keys_each_call():
    key1, _, _ = aes_ed("test")
    key2, _, _ = aes_ed("test")
    assert key1 != key2  # random key each time

def test_rsa_roundtrip():
    message = "Hello RSA"
    ciphertext, plaintext = rsa_ed(message)
    assert plaintext == message

def test_rsa_ciphertext_is_hex():
    ciphertext, _ = rsa_ed("test")
    assert all(c in "0123456789abcdef" for c in ciphertext)
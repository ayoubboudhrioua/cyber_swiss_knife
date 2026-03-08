import pytest
from modules.hashing.hash import hash_file, verify_integrity
import tempfile, os

def make_temp_file(content: bytes)-> str:
    f = tempfile.NamedTemporaryFile(delete=False)
    f.write(content)
    f.close()
    return f.name

def test_hash_file_returns_64_char_hex():
    path = make_temp_file(b"hello worlds")
    result = hash_file(path)
    os.unlink(path)
    assert len(result) == 64
    assert all(c in "0123456789abcdef" for c in result)
    
def test_hash_file_deterministic():
    path = make_temp_file(b"same content")
    assert hash_file(path) == hash_file(path)
    os.unlink(path)
    
def test_hash_file_different_content():
    p1 = make_temp_file(b"content a")
    p2 = make_temp_file(b"content b")
    assert hash_file(p1) != hash_file(p2)
    os.unlink(p1); os.unlink(p2)
    
def test_verify_integrity_identical_files():
    p1 = make_temp_file(b"identical")
    p2 = make_temp_file(b"identical")
    result = verify_integrity(p1,p2)
    os.unlink(p1); os.unlink(p2)
    assert "intact" in result.lower()

def test_verify_integrity_different_files():
    p1 = make_temp_file(b"file one")
    p2 = make_temp_file(b"file two")
    result = verify_integrity(p1, p2)
    os.unlink(p1); os.unlink(p2)
    assert "modified" in result.lower()

def test_hash_file_not_found():
    with pytest.raises(FileNotFoundError):
        hash_file("/nonexistent/path/file.txt")
    
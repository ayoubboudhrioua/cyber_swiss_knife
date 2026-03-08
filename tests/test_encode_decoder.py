import pytest
from modules.forensics.encoder_decoder import EncoderDecoder

@pytest.fixture
def ed():
    return EncoderDecoder()

def test_base64_roundtrip(ed):
    assert ed.decode_base64(ed.encode_base64("hello")) == "hello"

def test_hex_roundtrip(ed):
    assert ed.decode_hex(ed.encode_hex("hello")) == "hello"

def test_binary_roundtrip(ed):
    assert ed.decode_binary(ed.encode_binary("hi")) == "hi"

def test_url_roundtrip(ed):
    assert ed.decode_url(ed.encode_url("hello world")) == "hello world"

def test_rot13_roundtrip(ed):
    assert ed.decode_rot13(ed.encode_rot13("Hello World")) == "Hello World"

def test_rot13_is_symmetric(ed):
    assert ed.encode_rot13("abc") == ed.decode_rot13("abc")

def test_base64_invalid_input(ed):
    result = ed.decode_base64("!!!not valid base64!!!")
    assert "Error" in result
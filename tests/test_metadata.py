import pytest
import tempfile, os
from modules.forensics.metadata_extractor import MetadataExtractor

@pytest.fixture
def extractor():
    return MetadataExtractor()

def make_temp(content: bytes, suffix=".txt") -> str:
    f = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    f.write(content)
    f.close()
    return f.name

def test_metadata_keys_present(extractor):
    path = make_temp(b"hello world")
    meta = extractor.extract_metadata(path)
    os.unlink(path)
    assert "Basic Information" in meta
    assert "Timestamps" in meta
    assert "Hashes" in meta

def test_file_not_found_returns_error(extractor):
    meta = extractor.extract_metadata("/no/such/file.txt")
    assert "error" in meta

def test_sha256_correct_length(extractor):
    path = make_temp(b"test content")
    meta = extractor.extract_metadata(path)
    os.unlink(path)
    assert len(meta["Hashes"]["SHA-256"]) == 64

def test_text_file_detected(extractor):
    path = make_temp(b"plain text content here")
    meta = extractor.extract_metadata(path)
    os.unlink(path)
    assert "Text" in meta["Content Analysis"]["Type"]

def test_format_size(extractor):
    assert extractor.format_size(1024) == "1.00 KB"
    assert extractor.format_size(1024 * 1024) == "1.00 MB"
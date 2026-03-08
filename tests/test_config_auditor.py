import pytest, tempfile, os
from pathlib import Path
from modules.security_auditor.config_auditor import ConfigAuditor

@pytest.fixture
def auditor(): return ConfigAuditor()

def write_temp(content, suffix=".env"):
    f = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
    f.write(content)
    f.close()
    return f.name

def test_detects_hardcoded_password(auditor):
    path = write_temp('PASSWORD="hunter2"\n')
    findings = auditor.scan_file(Path(path))
    os.unlink(path)
    assert any(f["rule"] == "Hardcoded Password" for f in findings)

def test_detects_debug_mode(auditor):
    path = write_temp("DEBUG=True\n", ".py")
    findings = auditor.scan_file(Path(path))
    os.unlink(path)
    assert any(f["rule"] == "Debug Mode Enabled" for f in findings)

def test_detects_weak_secret(auditor):
    path = write_temp('SECRET_KEY="changeme"\n')
    findings = auditor.scan_file(Path(path))
    os.unlink(path)
    assert any("Secret" in f["rule"] for f in findings)

def test_clean_file_no_findings(auditor):
    path = write_temp("APP_NAME=MyApp\nPORT=8080\n")
    findings = auditor.scan_file(Path(path))
    os.unlink(path)
    assert findings == []

def test_comments_ignored(auditor):
    path = write_temp("# PASSWORD=secret\n# DEBUG=True\n")
    findings = auditor.scan_file(Path(path))
    os.unlink(path)
    assert findings == []
<div align="center">

<img src="assets/chimera_logo.png" alt="Chimera Logo" width="600"/>

*A comprehensive, modular cybersecurity toolkit for education and authorized security testing*

![Python](https://img.shields.io/badge/Python-3.13-blue?style=flat-square&logo=python)
![Tests](https://img.shields.io/badge/Tests-61%20passing-brightgreen?style=flat-square&logo=pytest)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square)

</div>

---

## Overview

Chimera is a terminal-based cybersecurity toolkit built in Python. It covers cryptography, password security, network analysis, security auditing, digital forensics, and attack simulation — all through a single Rich-powered interactive CLI. Built to be educational, modular, and extensible via a plugin system.

> ⚠️ **For authorized use only.** Educational purposes and testing systems you own or have permission to test.

---

## Features

### 🔒 Cryptography
| Command | Description |
|---------|-------------|
| `1.1` Hash File | SHA-256 file hashing with progress display |
| `1.2` Verify Integrity | Compare two files by hash |
| `1.3` AES Encryption | AES-256-GCM symmetric encryption + decryption |
| `1.4` RSA Encryption | RSA-2048 OAEP asymmetric encryption + decryption |

### 🔑 Password Security
| Command | Description |
|---------|-------------|
| `2.1` Password Manager | zxcvbn strength analysis + bcrypt hashing + verification |
| `2.2` Breach Checker | HaveIBeenPwned API via k-anonymity (your password never leaves your machine) |
| `2.3` Attack Simulator | Dictionary, brute-force, and rainbow table demos |
| `2.4` Password Policy | Validates against NIST, Corporate, and High-Security policies |
| `2.5` Entropy Visualizer | Real-time entropy meter, character histogram, crack-time estimates |
| `2.6` Password Generator | Cryptographically secure random passwords and passphrases |

### 🛡️ Security Auditing
| Command | Description |
|---------|-------------|
| `3.1` SSH Key Auditor | Scans `~/.ssh` for weak keys, bad permissions, and old keys |
| `3.2` SSL/TLS Checker | Certificate expiry and validity for multiple domains |
| `3.3` Git Secret Scanner | Detects committed API keys, tokens, and credentials |
| `3.4` Phishing Detector | Heuristic email analysis (domain, urgency, URL, spoofing) |
| `3.5` JWT Analyzer | Decodes JWTs, detects `alg:none` attacks, cracks weak HMAC secrets |
| `3.6` Config Auditor | Scans config files for hardcoded secrets and misconfigurations |

### 🌐 Network Tools
| Command | Description |
|---------|-------------|
| `4.1` Port Scanner | Concurrent TCP scanner with banner grabbing |
| `4.2` WHOIS Lookup | Domain registration info via direct WHOIS socket query |
| `4.3` IP Geolocation | IP location via ip-api.com with map link |

### 🔍 Forensics
| Command | Description |
|---------|-------------|
| `5.1` Encoder/Decoder | Base64, Hex, Binary, URL, ROT13 encode/decode |
| `5.2` Metadata Extractor | File hashes (MD5/SHA1/SHA256/SHA512), timestamps, entropy |
| `5.3` Steg Detector | LSB chi-square analysis, PNG chunk audit, JPEG EOI check |

### 📊 Reporting & Plugins
| Command | Description |
|---------|-------------|
| `6.1` Report Generator | Export scan results as HTML, JSON, or plain text |
| `7.1` Plugin Manager | Drop Python plugins into `plugins/` for auto-loading |

---

## Architecture
```
Chimera/
├── main_enhanced.py          # Entry point — Rich CLI + menu routing
├── modules/
│   ├── hashing/              # SHA-256 file hashing + integrity verification
│   ├── encryption/           # AES-256-GCM, RSA-2048 (cryptography lib)
│   ├── password/             # zxcvbn, bcrypt, HIBP, entropy, generator, policy
│   ├── attack_tools/         # Attack simulation + phishing detection
│   ├── security_auditor/     # SSH, SSL, git scanner, JWT, config auditor
│   ├── network/              # Port scanner, WHOIS, IP geolocation
│   ├── forensics/            # Encoder/decoder, metadata, steganography
│   ├── reporting/            # HTML/JSON/text report generation
│   └── plugins/              # Plugin manager + plugin base class
├── tests/                    # 61 pytest tests, 100% passing
├── plugins/                  # Drop custom plugins here
├── sample_files/             # Common password wordlist
└── requirements.txt
```

---

## Quick Start
```bash
# 1. Clone the repo
git clone https://github.com/yourusername/chimera.git
cd chimera

# 2. Create and activate a virtual environment
python -m venv myenv
# Windows:
myenv\Scripts\activate
# macOS/Linux:
source myenv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run
python main_enhanced.py

# 5. Run tests
pytest
```

---

## Writing a Plugin

Drop a `.py` file into the `plugins/` directory:
```python
from modules.plugins.plugins_manager import Pluginbase
from rich.console import Console

console = Console()

class MyPlugin(Pluginbase):
    def get_name(self):        return "my_plugin"
    def get_description(self): return "Does something cool"
    def get_version(self):     return "1.0.0"
    def get_category(self):    return "Custom"

    def execute(self):
        console.print("[green]Hello from my plugin![/green]")
```

The plugin manager auto-discovers and loads it on next launch.

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `rich` | Terminal UI, tables, panels, progress bars |
| `cryptography` | AES-256-GCM, RSA-2048 OAEP |
| `bcrypt` | Password hashing |
| `zxcvbn` | Password strength estimation |
| `requests` | HIBP API, IP geolocation |
| `pytest` + `pytest-cov` | Test suite |

---


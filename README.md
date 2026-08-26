# MO3 — Certificate Pinning Bypass

SSL pinning detection, certificate extraction, proxy configuration, and trust store manipulation tools.

## Overview

This tool assists with SSL/TLS certificate pinning analysis and bypass techniques:
- Detect SSL pinning implementations
- Extract and analyze certificates
- Configure proxy settings for MITM analysis
- Manage custom trust stores
- Validate certificate chains

## Features

- **SSL Pinning Detection**: Test hosts for pinning indicators
- **Certificate Extraction**: Save certificates in PEM/DER formats
- **Certificate Analysis**: Check for weaknesses and pin values
- **Proxy Configuration**: Generate configs for various tools
- **Trust Store Management**: Add/remove custom CA certificates
- **Certificate Validation**: Check for weak algorithms and expiry

## Installation

```bash
# No external dependencies required - uses standard library only
python3 cert_pin_analyzer.py <command> [options]
```

## Usage

```bash
# Detect SSL pinning
python3 cert_pin_analyzer.py detect example.com

# Extract certificate
python3 cert_pin_analyzer.py extract example.com

# Configure proxy
python3 cert_pin_analyzer.py proxy 127.0.0.1 8080

# Add certificate to trust store
python3 cert_pin_analyzer.py trust /path/to/cert.pem

# Analyze certificate
python3 cert_pin_analyzer.py analyze example.com

# Run demo mode
python3 cert_pin_analyzer.py
```

## Example Output

```
============================================================
  MO3 — Certificate Pinning Bypass Tool
============================================================

[*] Testing SSL pinning on example.com:443

============================================================
  MO3 — SSL Pinning Detection Report
============================================================

  Host: example.com:443
  Connection Possible: True
  Certificate Chain Length: 3
  Pinning Detected: Unlikely

============================================================
  Proxy Configuration Guide
============================================================

  Proxy URL: http://127.0.0.1:8080

  Environment Variables:
    export HTTP_PROXY=http://127.0.0.1:8080
    export HTTPS_PROXY=http://127.0.0.1:8080

  Python requests:
    proxies = {
        'http': 'http://127.0.0.1:8080',
        'https': 'http://127.0.0.1:8080',
    }
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT

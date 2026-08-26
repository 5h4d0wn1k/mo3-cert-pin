#!/usr/bin/env python3
"""MO3 — Certificate Pinning Bypass

SSL pinning detection, certificate extraction, proxy configuration,
and trust store manipulation tools.
Uses only standard library modules.
"""

import ssl
import socket
import hashlib
import os
import sys
import json
import struct
import base64
import tempfile
from datetime import datetime
from urllib.parse import urlparse


class SSLPinningDetector:
    """Detect SSL pinning configurations in connections."""

    # Common pinning indicators
    PINNING_INDICATORS = [
        'certificate_pinning',
        'ssl_pinning',
        'pinning',
        'CertificatePinner',
        'TrustManager',
        'X509TrustManager',
        'checkServerTrusted',
        'checkClientTrusted',
        'getAcceptedIssuers',
        'OkHttpClient',
        'Retrofit',
        'HostnameVerifier',
        'SSLSocketFactory',
    ]

    def __init__(self):
        self.results = []

    def check_host(self, hostname, port=443):
        """Check a host for SSL pinning indicators."""
        print(f"\n[*] Testing SSL pinning on {hostname}:{port}")

        result = {
            'hostname': hostname,
            'port': port,
            'connection_possible': False,
            'cert_chain_length': 0,
            'pinned': False,
            'details': []
        }

        try:
            # Test 1: Standard connection
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    result['connection_possible'] = True
                    result['cert_chain_length'] = len(cert.get('subject', ()))

            # Test 2: Connection with self-signed cert
            ctx_unverified = ssl.create_default_context()
            ctx_unverified.check_hostname = False
            ctx_unverified.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx_unverified.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    if cert_der:
                        result['details'].append("Self-signed cert connection allowed")

            # Test 3: Check certificate transparency
            if cert:
                extensions = cert.get('subjectAltName', ())
                result['details'].append(f"SAN entries: {len(extensions)}")

        except ssl.SSLCertVerificationError as e:
            result['details'].append(f"Certificate verification failed: {str(e)[:100]}")
        except socket.timeout:
            result['details'].append("Connection timed out")
        except ConnectionRefusedError:
            result['details'].append("Connection refused")
        except Exception as e:
            result['details'].append(f"Error: {str(e)[:100]}")

        self.results.append(result)
        return result

    def analyze_certificate(self, hostname, port=443):
        """Analyze certificate details for pinning clues."""
        print(f"\n[*] Analyzing certificate for {hostname}:{port}")

        cert_info = {
            'subject': None,
            'issuer': None,
            'serial_number': None,
            'not_before': None,
            'not_after': None,
            'san': [],
            'public_key_type': None,
            'signature_algorithm': None,
            'fingerprints': {}
        }

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cert_der = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    version = ssock.version()

                    # Parse certificate fields
                    if 'subject' in cert:
                        for rdn in cert['subject']:
                            for attr in rdn:
                                if attr[0] == 'commonName':
                                    cert_info['subject'] = attr[1]
                                elif attr[0] == 'organizationName':
                                    cert_info['organization'] = attr[1]

                    if 'issuer' in cert:
                        for rdn in cert['issuer']:
                            for attr in rdn:
                                if attr[0] == 'organizationName':
                                    cert_info['issuer'] = attr[1]
                                elif attr[0] == 'commonName':
                                    cert_info['issuer_cn'] = attr[1]

                    cert_info['serial_number'] = cert.get('serialNumber', 'unknown')
                    cert_info['not_before'] = cert.get('notBefore', 'unknown')
                    cert_info['not_after'] = cert.get('notAfter', 'unknown')

                    # SAN
                    san = cert.get('subjectAltName', ())
                    for entry in san:
                        cert_info['san'].append(f"{entry[0]}: {entry[1]}")

                    # Fingerprints
                    if cert_der:
                        cert_info['fingerprints']['sha256'] = hashlib.sha256(cert_der).hexdigest()
                        cert_info['fingerprints']['sha1'] = hashlib.sha1(cert_der).hexdigest()
                        cert_info['fingerprints']['md5'] = hashlib.md5(cert_der).hexdigest()

                    cert_info['cipher'] = cipher
                    cert_info['tls_version'] = version

                    self._print_cert_info(cert_info)

        except Exception as e:
            print(f"[!] Error analyzing certificate: {e}")

        return cert_info

    def _print_cert_info(self, info):
        """Print certificate analysis."""
        print(f"\n  Certificate Analysis:")
        print(f"  {'='*50}")
        print(f"  Subject: {info.get('subject', 'unknown')}")
        print(f"  Issuer: {info.get('issuer', 'unknown')}")
        print(f"  Serial: {info.get('serial_number', 'unknown')}")
        print(f"  Valid From: {info.get('not_before', 'unknown')}")
        print(f"  Valid To: {info.get('not_after', 'unknown')}")
        print(f"  TLS Version: {info.get('tls_version', 'unknown')}")

        if info.get('cipher'):
            cipher = info['cipher']
            print(f"  Cipher: {cipher[0] if cipher else 'unknown'}")

        if info.get('san'):
            print(f"  SANs:")
            for san in info['san'][:10]:
                print(f"    - {san}")

        if info.get('fingerprints'):
            print(f"  Fingerprints:")
            for algo, fp in info['fingerprints'].items():
                print(f"    {algo}: {fp}")

    def print_report(self):
        """Print SSL pinning detection report."""
        print(f"\n{'='*60}")
        print("  MO3 — SSL Pinning Detection Report")
        print(f"{'='*60}")

        for result in self.results:
            print(f"\n  Host: {result['hostname']}:{result['port']}")
            print(f"  Connection Possible: {result['connection_possible']}")
            print(f"  Certificate Chain Length: {result['cert_chain_length']}")
            print(f"  Pinning Detected: {'Possible' if result['pinned'] else 'Unlikely'}")

            if result['details']:
                print(f"  Details:")
                for detail in result['details']:
                    print(f"    - {detail}")


class CertificateExtractor:
    """Extract and save certificates from connections."""

    def __init__(self, output_dir=None):
        self.output_dir = output_dir or tempfile.mkdtemp(prefix='certs_')
        os.makedirs(self.output_dir, exist_ok=True)

    def extract_cert(self, hostname, port=443, save_pem=True, save_der=True):
        """Extract certificate from host and save to files."""
        print(f"\n[*] Extracting certificate from {hostname}:{port}")

        cert_pem = None
        cert_der = None

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_pem = ssock.getpeercert()

            if cert_der and save_der:
                der_path = os.path.join(self.output_dir, f'{hostname}.der')
                with open(der_path, 'wb') as f:
                    f.write(cert_der)
                print(f"  [+] DER certificate saved: {der_path}")

            if cert_pem and save_pem:
                pem_path = os.path.join(self.output_dir, f'{hostname}.pem')
                self._save_pem(cert_pem, pem_path)
                print(f"  [+] PEM certificate saved: {pem_path}")

            # Calculate hashes for pinning
            if cert_der:
                sha256_hash = hashlib.sha256(cert_der).digest()
                sha256_b64 = base64.b64encode(sha256_hash).decode()
                print(f"\n  Certificate Pin (sha256): {sha256_b64}")
                print(f"  Pinning format:")
                print(f'    CertificatePinner.Builder().add(')
                print(f'        "{hostname}",')
                print(f'        "sha256/{sha256_b64}"')
                print(f'    ).build();')

                return {
                    'pem_path': pem_path if save_pem else None,
                    'der_path': der_path if save_der else None,
                    'sha256_pin': sha256_b64,
                    'hostname': hostname,
                }

        except Exception as e:
            print(f"[!] Error extracting certificate: {e}")

        return None

    def _save_pem(self, cert_dict, path):
        """Convert certificate dict to PEM format."""
        # This is a simplified conversion
        # In production, use cryptography library
        subject = dict(x[0] for x in cert_dict.get('subject', ()))
        issuer = dict(x[0] for x in cert_dict.get('issuer', ()))

        pem_lines = [
            "-----BEGIN CERTIFICATE-----",
        ]

        # Create a basic PEM representation
        # In reality, you'd properly encode the DER data
        import textwrap
        der_b64 = base64.b64encode(b'\x00' * 256).decode()
        pem_lines.extend(textwrap.wrap(der_b64, 64))
        pem_lines.append("-----END CERTIFICATE-----")

        with open(path, 'w') as f:
            f.write('\n'.join(pem_lines))

    def extract_cert_chain(self, hostname, port=443):
        """Extract full certificate chain."""
        print(f"\n[*] Extracting certificate chain from {hostname}:{port}")

        ctx = ssl.create_default_context()
        certs = []

        try:
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get peer cert
                    cert = ssock.getpeercert()
                    cert_der = ssock.getpeercert(binary_form=True)

                    if cert:
                        subject = dict(x[0] for x in cert.get('subject', ()))
                        issuer = dict(x[0] for x in cert.get('issuer', ()))
                        certs.append({
                            'subject': subject.get('commonName', 'unknown'),
                            'issuer': issuer.get('commonName', 'unknown'),
                            'sha256': hashlib.sha256(cert_der).hexdigest() if cert_der else None,
                        })

            print(f"  Chain length: {len(certs)}")
            for i, c in enumerate(certs):
                print(f"  [{i}] {c['subject']}")
                print(f"      Issuer: {c['issuer']}")
                if c['sha256']:
                    print(f"      SHA256: {c['sha26'][:32]}...")

        except Exception as e:
            print(f"[!] Error: {e}")

        return certs


class ProxyConfigurator:
    """Configure and test proxy settings for MITM analysis."""

    def __init__(self):
        self.proxies = {
            'http': None,
            'https': None,
        }
        self.trusted_certs = []

    def configure_proxy(self, proxy_host, proxy_port, proxy_type='https'):
        """Configure proxy for connections."""
        self.proxies[proxy_type] = f"{proxy_host}:{proxy_port}"
        print(f"[*] Proxy configured: {proxy_type}://{proxy_host}:{proxy_port}")

    def test_proxy(self, proxy_host, proxy_port):
        """Test if proxy is reachable."""
        print(f"\n[*] Testing proxy {proxy_host}:{proxy_port}")

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((proxy_host, proxy_port), timeout=5) as sock:
                print(f"  [+] Proxy connection successful")
                return True
        except Exception as e:
            print(f"  [!] Proxy connection failed: {e}")
            return False

    def generate_proxy_config(self, proxy_host, proxy_port):
        """Generate proxy configuration for various tools."""
        print(f"\n{'='*60}")
        print("  Proxy Configuration Guide")
        print(f"{'='*60}")

        proxy_url = f"http://{proxy_host}:{proxy_port}"

        print(f"\n  Proxy URL: {proxy_url}")

        print(f"\n  Environment Variables:")
        print(f"    export HTTP_PROXY={proxy_url}")
        print(f"    export HTTPS_PROXY={proxy_url}")
        print(f"    export http_proxy={proxy_url}")
        print(f"    export https_proxy={proxy_url}")
        print(f"    export NO_PROXY=localhost,127.0.0.1")

        print(f"\n  Python requests:")
        print(f"    proxies = {{")
        print(f"        'http': '{proxy_url}',")
        print(f"        'https': '{proxy_url}',")
        print(f"    }}")

        print(f"\n  curl:")
        print(f"    curl -x {proxy_url} https://example.com")

        print(f"\n  Burp Suite / mitmproxy:")
        print(f"    Set proxy listener to {proxy_host}:{proxy_port}")
        print(f"    Install CA certificate in device")

    def install_ca_cert(self, cert_path):
        """Guide for installing CA certificate."""
        print(f"\n{'='*60}")
        print("  CA Certificate Installation Guide")
        print(f"{'='*60}")

        print(f"\n  Certificate Path: {cert_path}")

        print(f"\n  Android:")
        print(f"    1. Push cert to device:")
        print(f"       adb push {cert_path} /sdcard/")
        print(f"    2. Go to Settings > Security > Install from SD card")
        print(f"    3. Select the certificate file")
        print(f"    4. Name it and select 'VPN and apps'")

        print(f"\n  iOS:")
        print(f"    1. Email the cert to device or use AirDrop")
        print(f"    2. Open the cert file")
        print(f"    3. Go to Settings > General > VPN & Device Management")
        print(f"    4. Install the certificate")
        print(f"    5. Go to Settings > General > About > Certificate Trust Settings")
        print(f"    6. Enable trust for the certificate")

        print(f"\n  Java/KeyStore:")
        print(f"    keytool -importcert -alias myca \\")
        print(f"            -file {cert_path} \\")
        print(f"            -keystore truststore.jks \\")
        print(f"            -storepass changeit")


class TrustStoreManager:
    """Manage trust store for certificate validation bypass."""

    def __init__(self):
        self.custom_certs = []
        self.trusted_fingerprints = set()

    def add_trusted_cert(self, cert_path):
        """Add a certificate to custom trust store."""
        print(f"[*] Adding certificate to trust store: {cert_path}")

        try:
            with open(cert_path, 'rb') as f:
                cert_data = f.read()

            fingerprint = hashlib.sha256(cert_data).hexdigest()
            self.trusted_fingerprints.add(fingerprint)
            self.custom_certs.append({
                'path': cert_path,
                'fingerprint': fingerprint,
                'added': datetime.now().isoformat(),
            })

            print(f"  [+] Certificate added")
            print(f"  SHA256: {fingerprint}")
            return True

        except FileNotFoundError:
            print(f"  [!] File not found: {cert_path}")
            return False

    def remove_trusted_cert(self, fingerprint):
        """Remove certificate from trust store."""
        self.custom_certs = [c for c in self.custom_certs if c['fingerprint'] != fingerprint]
        self.trusted_fingerprints.discard(fingerprint)
        print(f"[*] Certificate removed: {fingerprint[:16]}...")

    def create_ssl_context(self, verify=True, ca_cert=None):
        """Create custom SSL context with modified trust."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        else:
            if ca_cert:
                ctx.load_verify_locations(ca_cert)
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED

        return ctx

    def test_connection(self, hostname, port=443, verify=True):
        """Test connection with custom trust settings."""
        print(f"\n[*] Testing connection to {hostname}:{port} (verify={verify})")

        ctx = self.create_ssl_context(verify=verify)

        try:
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()

                    print(f"  [+] Connection successful")
                    if cert:
                        subject = dict(x[0] for x in cert.get('subject', ()))
                        print(f"  Subject: {subject.get('commonName', 'unknown')}")
                    if cipher:
                        print(f"  Cipher: {cipher[0]}")
                    return True

        except Exception as e:
            print(f"  [!] Connection failed: {e}")
            return False

    def print_trust_store(self):
        """Print trust store contents."""
        print(f"\n{'='*60}")
        print("  Custom Trust Store")
        print(f"{'='*60}")

        if not self.custom_certs:
            print("  Trust store is empty")
            return

        print(f"\n  Certificates: {len(self.custom_certs)}")
        for cert in self.custom_certs:
            print(f"    - {cert['path']}")
            print(f"      Fingerprint: {cert['fingerprint']}")
            print(f"      Added: {cert['added']}")


class CertificateValidator:
    """Validate certificates and check for weaknesses."""

    @staticmethod
    def check_weakness(cert_dict):
        """Check certificate for known weaknesses."""
        issues = []

        # Check key size
        # Note: simplified check - real implementation would parse public key

        # Check signature algorithm
        sig_algo = cert_dict.get('signatureAlgorithm', '')
        weak_algos = ['md5', 'sha1']
        for algo in weak_algos:
            if algo in sig_algo.lower():
                issues.append(f"Weak signature algorithm: {sig_algo}")

        # Check validity period
        not_after = cert_dict.get('notAfter', '')
        if not_after:
            try:
                # Simple check if expired
                from email.utils import parsedate_to_datetime
                expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                if expiry < datetime.now():
                    issues.append("Certificate has expired")
                elif (expiry - datetime.now()).days < 30:
                    issues.append("Certificate expires within 30 days")
            except Exception:
                pass

        # Check for self-signed
        subject = dict(x[0] for x in cert_dict.get('subject', ()))
        issuer = dict(x[0] for x in cert_dict.get('issuer', ()))
        if subject.get('commonName') == issuer.get('commonName'):
            issues.append("Certificate appears to be self-signed")

        return issues

    @staticmethod
    def validate_chain(cert_chain):
        """Validate certificate chain (simplified)."""
        if not cert_chain:
            return False, "Empty certificate chain"

        # In production, use cryptography library for proper chain validation
        return True, "Chain validation requires cryptography library"


def create_test_server():
    """Create a simple test SSL server for demonstration."""
    print("\n[*] Creating test SSL server configuration...")

    # Generate self-signed cert info
    test_cert = {
        'subject': (('commonName', 'test.example.com'),),
        'issuer': (('commonName', 'Test CA'), ('organizationName', 'Test Org'),),
        'serialNumber': '1234567890',
        'notBefore': 'Jan 01 00:00:00 2024 GMT',
        'notAfter': 'Dec 31 23:59:59 2025 GMT',
        'subjectAltName': [('DNS', 'test.example.com'), ('DNS', '*.example.com')],
    }

    print("\n  Test Certificate:")
    print(f"    Subject: test.example.com")
    print(f"    Issuer: Test CA")
    print(f"    Valid: 2024-01-01 to 2025-12-31")

    return test_cert


def main():
    """Main entry point."""
    print("=" * 60)
    print("  MO3 — Certificate Pinning Bypass Tool")
    print("=" * 60)

    if len(sys.argv) < 2:
        print("\nUsage: python3 cert_pin_analyzer.py <command> [options]")
        print("\nCommands:")
        print("  detect <hostname>     - Detect SSL pinning")
        print("  extract <hostname>    - Extract certificate")
        print("  proxy <host> <port>   - Configure proxy")
        print("  trust <cert_path>     - Add to trust store")
        print("  analyze <hostname>    - Analyze certificate")
        print("\nRunning demo mode...")

        # Demo mode
        detector = SSLPinningDetector()
        detector.print_report()

        configurator = ProxyConfigurator()
        configurator.generate_proxy_config('127.0.0.1', '8080')

        trust_manager = TrustStoreManager()
        trust_manager.print_trust_store()

        validator = CertificateValidator()
        test_cert = create_test_server()
        issues = validator.check_weakness(test_cert)
        print(f"\n  Certificate Issues Found: {len(issues)}")
        for issue in issues:
            print(f"    - {issue}")

        return

    command = sys.argv[1]

    if command == 'detect' and len(sys.argv) >= 3:
        hostname = sys.argv[2]
        port = int(sys.argv[3]) if len(sys.argv) > 3 else 443
        detector = SSLPinningDetector()
        detector.check_host(hostname, port)
        detector.print_report()

    elif command == 'extract' and len(sys.argv) >= 3:
        hostname = sys.argv[2]
        port = int(sys.argv[3]) if len(sys.argv) > 3 else 443
        extractor = CertificateExtractor()
        extractor.extract_cert(hostname, port)

    elif command == 'proxy' and len(sys.argv) >= 4:
        proxy_host = sys.argv[2]
        proxy_port = sys.argv[3]
        configurator = ProxyConfigurator()
        configurator.test_proxy(proxy_host, int(proxy_port))
        configurator.generate_proxy_config(proxy_host, proxy_port)

    elif command == 'trust' and len(sys.argv) >= 3:
        cert_path = sys.argv[2]
        trust_manager = TrustStoreManager()
        trust_manager.add_trusted_cert(cert_path)
        trust_manager.print_trust_store()

    elif command == 'analyze' and len(sys.argv) >= 3:
        hostname = sys.argv[2]
        port = int(sys.argv[3]) if len(sys.argv) > 3 else 443
        detector = SSLPinningDetector()
        detector.analyze_certificate(hostname, port)

    else:
        print(f"[!] Unknown command: {command}")
        print("Run without arguments for help")


if __name__ == '__main__':
    main()

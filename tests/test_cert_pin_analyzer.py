#!/usr/bin/env python3
"""Deterministic offline tests for MO3 — certificate pinning analyzer."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cert_pin_analyzer as mo3


class TestPinningPresenceScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = mo3.PinningPresenceScanner()

    def test_detects_okhttp_pinning(self):
        text = '''CertificatePinner pinner = new CertificatePinner.Builder()
            .add("api.lab.example.com", "sha256/AAAA...")
            .build();'''
        hits = self.scanner.scan_text(text)
        descs = [h["description"] for h in hits]
        self.assertIn("OkHttp CertificatePinner", descs)
        self.assertTrue(any("SHA-256" in d for d in descs))

    def test_detects_weak_trustmanager(self):
        text = '''return new X509TrustManager() {
            public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {}
            public void getAcceptedIssuers() { throw new UnsupportedOperationException(); }
        };'''
        hits = self.scanner.scan_text(text)
        types = {h["type"] for h in hits}
        self.assertIn("weak_trust", types)
        self.assertIn("pin_presence", types)

    def test_clean_file_has_no_hits(self):
        text = "public int add(int a, int b) { return a + b; }"
        self.assertEqual(self.scanner.scan_text(text), [])

    def test_verdict_classification(self):
        pinned = mo3.PinningPresenceScanner().summarize(
            [{"file": "a.java", "hits": [{"type": "pin_presence"}]}])
        weak = mo3.PinningPresenceScanner().summarize(
            [{"file": "b.java", "hits": [{"type": "weak_trust"}]}])
        clean = mo3.PinningPresenceScanner().summarize([{"file": "c.java", "hits": []}])
        self.assertEqual(pinned[0]["verdict"], "PINNED")
        self.assertEqual(weak[0]["verdict"], "WEAK_TRUST")
        self.assertEqual(clean[0]["verdict"], "NO_PINNING")


class TestFixtures(unittest.TestCase):
    def test_fixture_corpus_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            created = mo3.create_pinning_fixtures(tmp)
            self.assertEqual(len(created), 4)
            scanner = mo3.PinningPresenceScanner()
            results = [scanner.scan_file(p) for p in sorted(created.values())]
            summary = scanner.summarize(results)
            verdicts = {s["file"]: s["verdict"] for s in summary}
            self.assertEqual(verdicts.get("pinned_okhttp.java"), "PINNED")
            self.assertEqual(verdicts.get("weak_trustmanager.java"), "WEAK_TRUST")
            self.assertEqual(verdicts.get("clean_crypto.java"), "NO_PINNING")
            self.assertEqual(verdicts.get("marker_strings.cpp"), "PINNED")


class TestTrustStoreAndValidator(unittest.TestCase):
    def test_trust_store_add(self):
        with tempfile.TemporaryDirectory() as tmp:
            cert_path = os.path.join(tmp, "c.pem")
            with open(cert_path, "wb") as f:
                f.write(b"-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n")
            ts = mo3.TrustStoreManager()
            self.assertTrue(ts.add_trusted_cert(cert_path))
            self.assertEqual(len(ts.custom_certs), 1)

    def test_missing_cert_returns_false(self):
        ts = mo3.TrustStoreManager()
        self.assertFalse(ts.add_trusted_cert("/nonexistent/cert.pem"))

    def test_weakness_checks(self):
        cert = {
            "signatureAlgorithm": "sha1WithRSAEncryption",
            "subject": (("commonName", "test.lab.example.com"),),
            "issuer": (("commonName", "test.lab.example.com"),),
            "notAfter": "Jan 01 00:00:00 2020 GMT",
        }
        issues = mo3.CertificateValidator.check_weakness(cert)
        joined = " ".join(issues)
        self.assertIn("Weak signature", joined)
        self.assertIn("self-signed", joined)


class TestDemo(unittest.TestCase):
    def test_demo_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc = mo3.run_demo(os.path.join(tmp, "reports"))
            self.assertEqual(rc, 0)
            report = os.path.join(tmp, "reports", "mo3_demo_report.json")
            self.assertTrue(os.path.exists(report))
            with open(report) as f:
                data = json.load(f)
            self.assertTrue(data["results"])


if __name__ == "__main__":
    unittest.main()
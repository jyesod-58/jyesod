"""Offline tests for the optional Burp normalizer; all payloads are synthetic."""

import base64
import gzip
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ET
import zlib

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("burp_normalizer", ROOT / "normalize_burp.py")
normalizer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(normalizer)


def response(body, headers=b""):
    return b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n" + headers + b"\r\n" + body


def document(*responses):
    root = ET.Element("items")
    for raw in responses:
        item = ET.SubElement(root, "item")
        ET.SubElement(item, "url").text = "https://example.test/synthetic"
        ET.SubElement(item, "request", {"base64": "true"}).text = base64.b64encode(b"GET /synthetic HTTP/1.1\r\nHost: example.test\r\n\r\n").decode()
        ET.SubElement(item, "response", {"base64": "true"}).text = base64.b64encode(raw).decode()
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


class NormalizeTests(unittest.TestCase):
    payload = '{"name":"가상회원","email":"demo@example.test"}'.encode()

    def check_body(self, raw, expected=None):
        converted, methods = normalizer.normalize_response(raw)
        head, body = converted.split(b"\r\n\r\n", 1)
        self.assertEqual(body, self.payload if expected is None else expected)
        self.assertNotIn(b"content-encoding:", head.lower())
        self.assertNotIn(b"transfer-encoding:", head.lower())
        self.assertIn(b"Content-Length: " + str(len(body)).encode(), head)
        return methods

    def test_gzip(self):
        self.assertEqual(self.check_body(response(gzip.compress(self.payload), b"Content-Encoding: gzip\r\n")), ["content:gzip"])

    def test_deflate_zlib(self):
        self.check_body(response(zlib.compress(self.payload), b"Content-Encoding: deflate\r\n"))

    def test_deflate_raw(self):
        codec = zlib.compressobj(wbits=-zlib.MAX_WBITS)
        compressed = codec.compress(self.payload) + codec.flush()
        self.check_body(response(compressed, b"Content-Encoding: deflate\r\n"))

    def test_content_coding_chain(self):
        compressed = zlib.compress(gzip.compress(self.payload))
        self.assertEqual(self.check_body(response(compressed, b"Content-Encoding: gzip, deflate\r\n")), ["content:deflate", "content:gzip"])

    def test_duplicate_encoding_header_chain(self):
        compressed = zlib.compress(gzip.compress(self.payload))
        self.check_body(response(compressed, b"Content-Encoding: gzip\r\nContent-Encoding: deflate\r\n"))

    def test_concatenated_gzip_members(self):
        self.check_body(response(gzip.compress(self.payload[:8]) + gzip.compress(self.payload[8:]), b"Content-Encoding: gzip\r\n"))

    def test_chunked_gzip_and_trailer(self):
        zipped = gzip.compress(self.payload)
        chunks = (f"{len(zipped):x};test=value\r\n".encode() + zipped + b"\r\n0\r\nX-Test: done\r\n\r\n")
        self.assertEqual(self.check_body(response(chunks, b"Content-Encoding: gzip\r\nTransfer-Encoding: chunked\r\nTrailer: X-Test\r\n")), ["transfer:chunked", "content:gzip"])

    def test_transfer_compression_chain(self):
        zipped = gzip.compress(self.payload)
        chunks = f"{len(zipped):x}\r\n".encode() + zipped + b"\r\n0\r\n\r\n"
        self.assertEqual(self.check_body(response(chunks, b"Transfer-Encoding: gzip, chunked\r\n")), ["transfer:chunked", "transfer:gzip"])

    def test_invalid_chunked_variants(self):
        for chunked in (b"5\r\nabc\r\n0\r\n\r\n", b"z\r\nabc\r\n", b"3\nabc\n0\n\n", b"3\r\nabc\r\n0\r\n\r\nextra"):
            with self.subTest(chunked=chunked), self.assertRaisesRegex(normalizer.NormalizationError, "invalid_chunked"):
                normalizer.normalize_response(response(chunked, b"Transfer-Encoding: chunked\r\n"))

    def test_gzip_crc_verification_preserved(self):
        compressed = bytearray(gzip.compress(self.payload))
        compressed[-8] ^= 1
        with self.assertRaisesRegex(normalizer.NormalizationError, "invalid_compression"):
            normalizer.normalize_response(response(bytes(compressed), b"Content-Encoding: gzip\r\n"))

    def test_decompressed_size_limit(self):
        raw = response(gzip.compress(b"x" * 5000), b"Content-Encoding: gzip\r\n")
        with self.assertRaisesRegex(normalizer.NormalizationError, "response_limit"):
            normalizer.normalize_response(raw, limit=500)

    def test_chunked_declared_size_limit(self):
        with self.assertRaisesRegex(normalizer.NormalizationError, "response_limit"):
            normalizer.dechunk(b"ffffffff\r\n", 500)

    def test_xml_size_limit(self):
        with mock.patch.object(normalizer, "MAX_XML_BYTES", 10), self.assertRaisesRegex(ValueError, "input_xml_limit"):
            normalizer.normalize_document(document(response(self.payload)))

    def test_burp_internal_schema_dtd_allowed(self):
        xml = document(response(self.payload)).replace(b"<items>", b"<!DOCTYPE items [<!ELEMENT items (item*)><!ELEMENT item ANY>]><items>")
        self.assertEqual(normalizer.normalize_document(xml)[1]["normalized"], 1)

    def test_custom_entities_rejected(self):
        xml = b'<!DOCTYPE items [<!ENTITY fake "data">]><items><item/></items>'
        with self.assertRaisesRegex(ValueError, "xml_entities_not_supported"):
            normalizer.normalize_document(xml)

    def test_per_item_failure_isolation_and_original_preserved(self):
        good = response(gzip.compress(self.payload), b"Content-Encoding: gzip\r\n")
        bad = response(b"corrupt", b"Content-Encoding: gzip\r\n")
        before = ET.fromstring(document(good, bad))
        output, stats = normalizer.normalize_document(document(good, bad))
        after = ET.fromstring(output)
        self.assertEqual((stats["normalized"], stats["failed"]), (1, 1))
        self.assertEqual(after[0].findtext("request"), before[0].findtext("request"))
        self.assertEqual(after[1].findtext("request"), before[1].findtext("request"))
        self.assertEqual(base64.b64decode(after[0].findtext("originalResponse")), good)
        self.assertEqual(after[1].findtext("response"), before[1].findtext("response"))
        self.assertEqual(after[1].findtext("normalizationError"), "invalid_compression")

    def test_invalid_base64_item_isolated(self):
        xml = b'<items><item><response base64="true">!!!</response></item></items>'
        output, stats = normalizer.normalize_document(xml)
        self.assertEqual(stats["failed"], 1)
        self.assertEqual(ET.fromstring(output)[0].findtext("response"), "!!!")

    def test_missing_brotli_fixed_reason(self):
        with mock.patch.object(normalizer.importlib, "import_module", side_effect=ImportError()):
            with self.assertRaisesRegex(normalizer.NormalizationError, "missing_brotli"):
                normalizer.normalize_response(response(b"dummy", b"Content-Encoding: br\r\n"))

    @unittest.skipUnless(importlib.util.find_spec("brotli"), "optional brotli package is not installed")
    def test_brotli_when_available(self):
        import brotli
        self.check_body(response(brotli.compress(self.payload), b"Content-Encoding: br\r\n"))

    def test_cli_partial_exit_two_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.xml"
            target = Path(directory) / "output.xml"
            initial = document(response(self.payload), response(b"bad", b"Content-Encoding: gzip\r\n"))
            source.write_bytes(initial)
            run = subprocess.run([sys.executable, str(ROOT / "normalize_burp.py"), str(source), str(target)], capture_output=True, text=True)
            self.assertEqual(run.returncode, 2, run.stderr)
            self.assertIn("total=2 normalized=1 failed=1", run.stdout)
            self.assertIn("item=2 error=invalid_compression", run.stdout)
            self.assertNotIn("demo@example.test", run.stdout)
            self.assertEqual(source.read_bytes(), initial)
            written = target.read_bytes()
            repeat = subprocess.run([sys.executable, str(ROOT / "normalize_burp.py"), str(source), str(target)], capture_output=True, text=True)
            self.assertEqual(repeat.returncode, 1)
            self.assertEqual(target.read_bytes(), written)

    def test_cli_full_success_exit_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.xml"
            target = Path(directory) / "output.xml"
            source.write_bytes(document(response(gzip.compress(self.payload), b"Content-Encoding: gzip\r\n")))
            run = subprocess.run([sys.executable, str(ROOT / "normalize_burp.py"), str(source), str(target)], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertIn("total=1 normalized=1 failed=0", run.stdout)


if __name__ == "__main__":
    unittest.main()

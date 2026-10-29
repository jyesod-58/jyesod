"""Small offline checks of the large-fixture writer; no browser required."""
import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from xml.etree import ElementTree as ET

from large_test_fixtures import BLOCK, MIB, write_fixture


class FixtureChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'synthetic.xml'

    def test_exact_byte_boundaries_and_hash(self):
        for offset in (-1, 0, 1):
            with self.subTest(offset=offset):
                path = self.path.with_name(f'synthetic-{offset}.xml')
                manifest = write_fixture(path, size_bytes=MIB + offset)
                data = path.read_bytes()
                self.assertEqual(len(data), MIB + offset)
                self.assertEqual(hashlib.sha256(data).hexdigest(), manifest['sha256'])
                self.assertEqual(len(ET.fromstring(data).findall('item')), 1)

    def test_many_records_have_exact_size_and_valid_json(self):
        manifest = write_fixture(self.path, size_bytes=2 * MIB, mode='records', body_bytes=64 * 1024)
        root = ET.parse(self.path).getroot()
        self.assertGreater(manifest['expected_items'], 10)
        self.assertEqual(manifest['expected_items'], len(root.findall('item')))
        self.assertEqual(self.path.stat().st_size, 2 * MIB)
        for index, item in enumerate(root, 1):
            raw = base64.b64decode(item.find('response').text, validate=True)
            head, body = raw.split(b'\r\n\r\n', 1)
            self.assertEqual(len(body), 64 * 1024)
            self.assertIn(b'Content-Length: 65536', head)
            record = json.loads(body)
            self.assertEqual(record['record'], index)
            self.assertEqual(record['email'], f'member{index}@example.test')

    def test_cdata_item_end_and_delimiter_across_chunk_boundary(self):
        manifest = write_fixture(self.path, size_bytes=2 * MIB, mode='cdata', cdata_boundary=BLOCK)
        data = self.path.read_bytes()
        start = manifest['cdata_close_offset']
        self.assertEqual(start, BLOCK - 1)
        self.assertEqual(data[start:start + 3], b']]>')
        root = ET.fromstring(data)
        self.assertEqual(len(root.findall('item')), 1)
        raw = root.find('item/response').text
        record = json.loads(raw.split('\r\n\r\n', 1)[1] if '\r\n\r\n' in raw else raw.split('\n\n', 1)[1])
        self.assertIn('</item>', record['note'])
        self.assertIn(']]>', record['note'])

    def test_whitespace_padding_and_existing_file_protection(self):
        manifest = write_fixture(self.path, size_bytes=4096, padding='whitespace')
        self.assertEqual(manifest['bytes'], 4096)
        self.assertNotIn(b'<!--', self.path.read_bytes())
        with self.assertRaises(FileExistsError):
            write_fixture(self.path, size_bytes=4096)


if __name__ == '__main__':
    unittest.main()

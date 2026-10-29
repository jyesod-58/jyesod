"""Offline synthetic regression checks; third-party dependencies are not imported.

Run: python -m unittest discover -s tests -p 'test_crawler_server.py' -v
"""
import ast
import asyncio
import base64
import io
import json
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load_crawler():
    tree = ast.parse((ROOT / 'crawler.py').read_text(encoding='utf-8'))
    safe_imports = {'__future__', 'argparse', 'asyncio', 'base64', 'json', 'os', 're', 'sys', 'datetime', 'pathlib', 'urllib.error', 'urllib.parse', 'urllib.request', 'urllib.robotparser', 'xml.sax.saxutils'}
    nodes = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Assign)):
            nodes.append(node)
        elif isinstance(node, ast.Import) and all(alias.name in safe_imports for alias in node.names):
            nodes.append(node)
        elif isinstance(node, ast.ImportFrom) and node.module in safe_imports:
            nodes.append(node)
    ns = {'__name__': 'crawler_test_extract'}
    exec(compile(ast.Module(nodes, type_ignores=[]), str(ROOT / 'crawler.py'), 'exec'), ns)
    return ns


def load_server(crawler):
    tree = ast.parse((ROOT / 'webapp.py').read_text(encoding='utf-8'))
    nodes = [node for node in tree.body if not (
        isinstance(node, ast.Import) and any(alias.name == 'crawler' for alias in node.names)
    ) and not (isinstance(node, ast.If) and isinstance(node.test, ast.Compare))]
    ns = {'__file__': str(ROOT / 'webapp.py'), '__name__': 'webapp_test_extract', 'crawler': SimpleNamespace(**crawler)}
    exec(compile(ast.Module(nodes, type_ignores=[]), str(ROOT / 'webapp.py'), 'exec'), ns)
    ns['_real_get_crawler'] = ns['_get_crawler']
    ns['_get_crawler'] = lambda: SimpleNamespace(**crawler)
    return ns


class CaptureChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ns = load_crawler()

    def test_scope_does_not_cross_public_suffix(self):
        self.assertFalse(self.ns['_same_site']('other.go.kr', 'approved.go.kr', True))
        self.assertFalse(self.ns['_same_site']('approved.go.kr.evil.test', 'approved.go.kr', True))
        self.assertTrue(self.ns['_same_site']('www.approved.go.kr', 'approved.go.kr', True))
        self.assertFalse(self.ns['_same_site']('www.approved.go.kr', 'approved.go.kr', False))

    def test_scope_rejects_non_http_and_url_credentials(self):
        self.assertFalse(self.ns['_in_scope']('file:///tmp/data', {'approved.go.kr'}))
        self.assertFalse(self.ns['_in_scope']('https://user@approved.go.kr/', {'approved.go.kr'}))
        self.assertTrue(self.ns['_in_scope']('https://approved.go.kr:443/', {'approved.go.kr'}))

    def test_encoded_password_and_headers_are_masked(self):
        request = SimpleNamespace(url='https://example.test/', method='POST',
                                  headers={'content-type': 'application/x-www-form-urlencoded', 'cookie': 'session=synthetic', 'authorization': 'Bearer synthetic'},
                                  post_data_buffer=b'password=A%26B%2b')
        raw = self.ns['_raw_request'](request, ['A&B+'])
        self.assertNotIn(b'session=synthetic', raw)
        self.assertNotIn(b'Bearer synthetic', raw)
        self.assertNotIn(b'A%26B%2b', raw)
        self.assertIn(b'password=***REDACTED***', raw)

    def test_euc_kr_body_and_response_headers(self):
        class Response:
            status = 200
            async def body(self):
                return '이름: 합성예시 암호: 비밀'.encode('euc-kr')
            async def all_headers(self):
                return {'content-type': 'text/plain; charset=euc-kr', 'set-cookie': 'synthetic=token', 'content-length': '999'}
        raw = asyncio.run(self.ns['_raw_response'](Response(), ['비밀']))
        head, body = raw.split(b'\r\n\r\n', 1)
        self.assertEqual(body.decode('euc-kr'), '이름: 합성예시 암호: ***REDACTED***')
        self.assertNotIn(b'synthetic=token', head)
        self.assertIn(f'Content-Length: {len(body)}'.encode(), head)

    def test_all_transactions_are_retained(self):
        doc = SimpleNamespace(metadata={'url': 'https://example.test/', 'title': 'test', 'status': 200, 'fetched_at': '2026-01-01'}, page_content='test')
        def exchange(value):
            return {'url': 'https://example.test/api', 'method': 'POST', 'status': 200, 'mime': 'application/json', 'request_b64': '', 'response_b64': base64.b64encode(value).decode()}
        inputs = [{'ok': True, 'doc': doc, 'exchanges': [exchange(b'A'), exchange(b'B'), exchange(b'A')]}]
        with tempfile.TemporaryDirectory() as folder:
            out, count = self.ns['save_outputs'](inputs, SimpleNamespace(out=folder, max_chars=20000))
            self.assertEqual(count, 3)
            self.assertEqual((out / 'burp_history.xml').read_text().count('<item>'), 3)

    def scoped_route(self, url, status=200, location=None):
        tree = ast.parse((ROOT / 'crawler.py').read_text(encoding='utf-8'))
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef) and n.name == 'scoped_route')
        ns = dict(self.ns)
        ns.update(args=SimpleNamespace(approved_hosts={'approved.go.kr'}, allow_subdomains=False), log=lambda msg: None)
        exec(compile(ast.Module([node], type_ignores=[]), 'scope-route-extract', 'exec'), ns)
        class Route:
            request = SimpleNamespace(url=url)
            calls = []
            async def abort(self, reason):
                self.calls.append(('abort', reason))
            async def fetch(self, **kwargs):
                self.calls.append(('fetch', kwargs))
                return SimpleNamespace(status=status, headers={'location': location} if location else {})
            async def fulfill(self, **kwargs):
                self.calls.append(('fulfill', None))
        route = Route()
        asyncio.run(ns['scoped_route'](route))
        return route.calls

    def test_route_blocks_foreign_host_before_fetch(self):
        self.assertEqual(self.scoped_route('https://other.go.kr/'), [('abort', 'blockedbyclient')])

    def test_route_disables_redirect_following(self):
        calls = self.scoped_route('https://approved.go.kr/')
        self.assertEqual(calls[0], ('fetch', {'url': 'https://approved.go.kr/', 'max_redirects': 0}))
        self.assertEqual(calls[1][0], 'fulfill')

    def test_route_blocks_redirects_without_following(self):
        for location in ('https://other.go.kr/', '/final'):
            with self.subTest(location=location):
                calls = self.scoped_route('https://approved.go.kr/', 302, location)
                self.assertEqual(len(calls), 2)
                self.assertEqual(calls[1], ('abort', 'blockedbyclient'))


class ServerChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ns = load_server(load_crawler())

    def request(self, method='POST', path='/api/stop', headers=None, body=b'{}'):
        handler = object.__new__(self.ns['Handler'])
        handler.path = path
        handler.server = SimpleNamespace(server_address=('127.0.0.1', 8777))
        handler.headers = {'Host': '127.0.0.1:8777', 'Origin': 'http://127.0.0.1:8777', 'X-Local-Token': self.ns['API_TOKEN'], 'Content-Type': 'application/json', 'Content-Length': str(len(body))}
        handler.headers.update(headers or {})
        handler.rfile = io.BytesIO(body)
        result = {}
        handler._send = lambda code, raw, ctype='application/json', extra=None: result.update(status=code, raw=raw)
        getattr(handler, 'do_' + method)()
        return result

    def test_valid_authenticated_request(self):
        self.assertEqual(self.request()['status'], 200)

    def test_foreign_origin_rejected(self):
        self.assertEqual(self.request(headers={'Origin': 'https://foreign.example.test'})['status'], 403)

    def test_rebinding_host_rejected(self):
        self.assertEqual(self.request(headers={'Host': 'foreign.example.test:8777'})['status'], 403)

    def test_missing_api_token_rejected(self):
        self.assertEqual(self.request(headers={'X-Local-Token': ''})['status'], 403)

    def test_simple_content_type_rejected(self):
        self.assertEqual(self.request(headers={'Content-Type': 'text/plain'})['status'], 415)

    def test_large_body_rejected_before_read(self):
        self.assertEqual(self.request(headers={'Content-Length': str(1024 * 1024 + 1)})['status'], 413)

    def test_non_object_json_rejected(self):
        self.assertEqual(self.request(body=b'[]')['status'], 400)

    def test_download_requires_token_and_safe_name(self):
        self.assertEqual(self.request(method='GET', path='/api/download?name=results.json', headers={'X-Local-Token': ''})['status'], 403)
        self.assertEqual(self.request(method='GET', path='/api/download?name=../../webapp.py')['status'], 404)

    def test_session_path_rejected(self):
        args_fn = self.ns['_args_from_request']
        for name in ('../session.json', '/tmp/session.json', 'bad/name.json', 'session.txt'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                args_fn({'session': name})
        args, _ = args_fn({'session': 'review-session.json'})
        self.assertEqual(Path(args.session).parent, ROOT / 'output')

    def test_html_has_injected_token(self):
        result = self.request(method='GET', path='/')
        self.assertEqual(result['status'], 200)
        self.assertNotIn(b'__LOCAL_API_TOKEN__', result['raw'])
        self.assertIn(self.ns['API_TOKEN'].encode(), result['raw'])

    def test_private_cache_headers(self):
        handler = object.__new__(self.ns['Handler'])
        headers = {}
        handler.send_response = lambda code: None
        handler.send_header = lambda key, value: headers.update({key: value})
        handler.end_headers = lambda: None
        handler.wfile = io.BytesIO()
        handler._send(200, b'synthetic')
        self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertEqual(headers['X-Content-Type-Options'], 'nosniff')

    def test_missing_crawler_dependency_has_install_guidance(self):
        missing = ModuleNotFoundError("synthetic missing dependency", name='synthetic_dependency')
        with patch('builtins.__import__', side_effect=missing):
            with self.assertRaisesRegex(ModuleNotFoundError, 'pip install -r requirements.txt'):
                self.ns['_real_get_crawler']()

    def test_failed_lazy_import_is_reported_as_job_error(self):
        original = self.ns['_get_crawler']
        self.ns['_get_crawler'] = lambda: (_ for _ in ()).throw(ModuleNotFoundError('synthetic dependency unavailable'))
        try:
            job = self.ns['_new_job']()
            self.ns['_run_job'](job, {})
            self.assertEqual(job['state'], 'error')
            self.assertIn('synthetic dependency unavailable', job['error'])
        finally:
            self.ns['_get_crawler'] = original


if __name__ == '__main__':
    unittest.main()

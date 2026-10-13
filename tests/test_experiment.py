import asyncio
import json
import tempfile
import unittest
from pathlib import Path

try:
    import honeypot
except ImportError:
    honeypot = None


class ExperimentTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.assertIsNotNone(honeypot, 'honeypot implementation is missing')
        self.tmp = tempfile.TemporaryDirectory()
        self.state = honeypot.State(Path(self.tmp.name), per_ip=2, global_limit=20)
        self.server = await asyncio.start_server(self.state.handle, '127.0.0.1', 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        if hasattr(self, 'server'):
            self.server.close()
            await self.server.wait_closed()
            self.state.db.close()
            self.tmp.cleanup()

    async def request(self, path='/v1/lures/example-env/status', headers='', method='GET', body=''):
        reader, writer = await asyncio.open_connection('127.0.0.1', self.port)
        writer.write(f'{method} {path} HTTP/1.1\r\nHost: localhost\r\n{headers}\r\n{body}'.encode())
        await writer.drain()
        data = await reader.read()
        writer.close()
        await writer.wait_closed()
        return data

    async def test_fixed_reply_and_no_tokens_body_raw_ip_or_unknown_path_saved(self):
        response = await self.request(headers='Authorization: Bearer private-token\r\nUser-Agent: unit-agent\r\n', body='private-body')
        self.assertIn(b'200 OK', response)
        self.assertEqual(json.loads(response.split(b'\r\n\r\n')[1]), {'ok': True, 'data': 'fictional-test-response'})
        await self.request('/private-path-token?token=query-secret')
        rows = self.state.events()
        rendered = json.dumps(rows)
        for secret in ['private-token', 'private-body', 'private-path-token', 'query-secret', '127.0.0.1']:
            self.assertNotIn(secret, rendered)
        self.assertEqual(rows[1]['route'], '/unknown')
        self.assertEqual(rows[0]['user_agent'], 'unit-agent')
        self.assertEqual(len(rows[0]['ip_hash']), 64)
        self.assertTrue(rows[0]['utc'].endswith('Z'))

    async def test_marked_tests_are_excluded_and_marker_spoof_does_not_exclude(self):
        await self.request(headers=f'X-Experiment-Test: {self.state.test_marker}\r\n')
        await self.request(headers='X-Experiment-Test: wrong\r\n')
        stats = self.state.summary()
        self.assertEqual(stats['total'], 1)
        self.assertEqual(stats['test_requests'], 1)
        self.assertEqual(stats['new_last_minute'], 1)
        self.assertEqual(stats['unique_ip_hashes'], 1)
        self.assertIsNone(stats['seconds_publication_to_first_request'])
        self.assertEqual(stats['by_lure']['example-env']['total'], 1)

    async def test_rate_rejections_are_counted(self):
        await self.request()
        await self.request()
        response = await self.request()
        self.assertIn(b'429 Too Many Requests', response)
        self.assertEqual(self.state.summary()['total'], 3)
        self.assertEqual(self.state.summary()['rate_limited'], 1)

    async def test_forwarding_headers_are_not_trusted_by_default(self):
        await self.request(headers='X-Honeypot-Client-IP: 203.0.113.10\r\nX-Forwarded-For: 203.0.113.11\r\n')
        await self.request(headers='X-Honeypot-Client-IP: 203.0.113.12\r\n')
        self.assertEqual(self.state.summary()['unique_ip_hashes'], 1)

    async def test_bad_methods_and_bodies_are_not_executed(self):
        reply = await self.request(method='POST', headers='Content-Length: 99999\r\n', body='command=whoami')
        self.assertIn(b'405 Method Not Allowed', reply)
        self.assertNotIn('command', json.dumps(self.state.events()))

    async def test_header_bound_and_slow_request_deadline(self):
        reader, writer = await asyncio.open_connection('127.0.0.1', self.port)
        writer.write(b'GET / HTTP/1.1\r\nX: ' + b'a' * 9000)
        await writer.drain()
        reply = await asyncio.wait_for(reader.read(), 2)
        self.assertIn(b'431 Request Header Fields Too Large', reply)
        writer.close()
        await writer.wait_closed()
        self.state.header_timeout = 0.05
        reader, writer = await asyncio.open_connection('127.0.0.1', self.port)
        writer.write(b'GET /')
        await writer.drain()
        reply = await asyncio.wait_for(reader.read(), 1)
        self.assertIn(b'408 Request Timeout', reply)
        writer.close()
        await writer.wait_closed()

    async def test_publication_baseline_and_export(self):
        self.state.set_publication('2026-01-01T00:00:00Z')
        await self.request('/v1/lures/python-client/status')
        stats = self.state.summary()
        self.assertGreater(stats['seconds_publication_to_first_request'], 0)
        self.assertEqual(stats['by_lure']['python-client']['total'], 1)
        self.state.export()
        self.assertEqual(json.loads((Path(self.tmp.name) / 'summary.json').read_text())['total'], 1)
        self.assertIn('ip_hash', (Path(self.tmp.name) / 'events.csv').read_text())

    async def test_csv_formula_neutralization(self):
        await self.request(headers='User-Agent: =malicious()\r\n')
        self.state.export()
        self.assertIn("'=malicious()", (Path(self.tmp.name) / 'events.csv').read_text())

    async def test_malformed_requests_consume_global_admission(self):
        self.state.global_limit = 1
        await self.request(method='BAD METHOD')
        response = await self.request(method='BAD METHOD')
        self.assertIn(b'429 Too Many Requests', response)
        self.assertEqual(self.state.summary()['rate_limited'], 1)

    async def test_proxy_errors_do_not_count_proxy_as_client(self):
        self.state.trust_proxy = True
        response = await self.request(headers='X-Honeypot-Client-IP: bad-address\r\n')
        self.assertIn(b'400 Bad Request', response)
        stats = self.state.summary()
        self.assertEqual(stats['unique_ip_hashes'], 0)
        self.assertEqual(stats['unattributed_requests'], 1)

    async def test_proxy_attribution_and_prepublication_exclusion(self):
        self.state.trust_proxy = True
        await self.request(headers='X-Honeypot-Client-IP: 203.0.113.10\r\n')
        self.state.set_publication('2099-01-01T00:00:00Z')
        self.assertEqual(self.state.summary()['total'], 0)
        self.assertEqual(self.state.summary()['prepublication_requests'], 1)
        with self.assertRaises(ValueError):
            self.state.set_publication('2099-01-02T00:00:00Z')

    async def test_head_reply_has_no_body(self):
        response = await self.request(method='HEAD')
        self.assertIn(b'200 OK', response)
        self.assertEqual(response.split(b'\r\n\r\n')[1], b'')

    async def test_global_limit_and_bucket_memory_bound(self):
        self.state.global_limit = 1
        await self.request()
        self.assertIn(b'429 Too Many Requests', await self.request())
        self.assertEqual(self.state.summary()['rate_limited'], 1)


if __name__ == '__main__':
    unittest.main()

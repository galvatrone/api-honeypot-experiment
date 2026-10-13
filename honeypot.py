"""Dedicated inert API. Python 3.11+, no third-party dependencies."""
import argparse
import asyncio
import csv
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time
from datetime import datetime, timezone

ROUTES = {f'/v1/lures/{lure}/status': lure for lure in ('example-env', 'python-client')}
BODY = b'{"ok":true,"data":"fictional-test-response"}\n'


def utc():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def timestamp(value):
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.utcoffset() is None:
        raise ValueError('UTC offset required')
    return result.timestamp()


def state_path(value):
    path = Path(value).expanduser().resolve()
    repo = Path(__file__).resolve().parent
    if path == repo or repo in path.parents:
        raise ValueError('Runtime directory must be outside the repository')
    return path


def private_file(path, content):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(content)


class State:
    def __init__(self, directory, per_ip=30, global_limit=300, trust_proxy=False):
        self.directory = state_path(directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.directory, 0o700)
        for name in ('salt', 'test-marker'):
            path = self.directory / name
            if not path.exists():
                try:
                    private_file(path, secrets.token_hex(32))
                except FileExistsError:
                    pass
        self.salt = (self.directory / 'salt').read_bytes()
        self.test_marker = (self.directory / 'test-marker').read_text().strip()
        self.db = sqlite3.connect(self.directory / 'events.sqlite', timeout=2)
        os.chmod(self.directory / 'events.sqlite', 0o600)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA max_page_count=32768')  # ~128 MiB at default 4 KiB pages
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY, utc TEXT NOT NULL, route TEXT NOT NULL,
            user_agent TEXT NOT NULL, lure_id TEXT NOT NULL, ip_hash TEXT NOT NULL,
            is_test INTEGER NOT NULL, status INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS events_time ON events(utc);
        CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        ''')
        self.db.commit()
        self.per_ip = per_ip
        self.global_limit = global_limit
        self.trust_proxy = trust_proxy
        self.header_timeout = 3
        self.buckets = {}
        self.window = -1
        self.count = 0
        self.active = 0
        self.max_connections = 32

    def record(self, route, agent, lure, ip_hash, is_test, status):
        self.db.execute('INSERT INTO events VALUES (NULL,?,?,?,?,?,?,?)',
                        (utc(), route, agent, lure, ip_hash, int(is_test), status))
        self.db.commit()

    def events(self):
        self.db.row_factory = sqlite3.Row
        return [dict(row) for row in self.db.execute('SELECT * FROM events ORDER BY id')]

    def metadata(self):
        return dict(self.db.execute('SELECT key,value FROM metadata'))

    def set_publication(self, value):
        timestamp(value)
        existing = self.metadata().get('published_utc')
        if existing and existing != value:
            raise ValueError('Publication baseline already recorded; refusing overwrite')
        self.db.execute('INSERT OR IGNORE INTO metadata VALUES (?,?)', ('published_utc', value))
        self.db.commit()

    def admit_global(self):
        window = int(time.monotonic() // 60)
        if self.window != window:
            self.window, self.count, self.buckets = window, 0, {}
        self.count += 1
        return self.count <= self.global_limit

    def allowed_ip(self, ip_hash):
        # At most global_limit distinct buckets per fixed window.
        if self.count > self.global_limit:
            return False
        self.buckets[ip_hash] = self.buckets.get(ip_hash, 0) + 1
        return self.buckets[ip_hash] <= self.per_ip

    async def handle(self, reader, writer):
        if self.active >= self.max_connections:
            writer.close()
            return  # Connection cap rejects before HTTP parsing; no telemetry claim.
        self.active += 1
        status = 400
        route, lure, agent = '/unparsed', 'unknown', ''
        is_test = False
        peer_ip = writer.get_extra_info('peername')[0]
        ip_hash = '' if self.trust_proxy else hmac.new(self.salt, peer_ip.encode(), hashlib.sha256).hexdigest()
        admitted = self.admit_global()
        if not self.trust_proxy and admitted:
            admitted = self.allowed_ip(ip_hash)
        try:
            raw = bytearray()
            deadline = time.monotonic() + self.header_timeout
            while b'\r\n\r\n' not in raw:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                chunk = await asyncio.wait_for(reader.read(min(1024, 8193 - len(raw))), remaining)
                if not chunk:
                    raise ValueError
                raw.extend(chunk)
                if len(raw) > 8192:
                    status = 431
                    raise ValueError
            # Bodies received in the same TCP chunk are discarded, never decoded/logged.
            head = bytes(raw).split(b'\r\n\r\n', 1)[0].decode('ascii')
            first, *lines = head.split('\r\n')
            method, target, version = first.split(' ')
            if version != 'HTTP/1.1' or not target.startswith('/'):
                raise ValueError
            path = target.split('?', 1)[0]
            route = path if path in ROUTES else '/unknown'
            lure = ROUTES.get(path, 'unknown')
            headers = {}
            for line in lines:
                key, value = line.split(':', 1)
                key = key.lower()
                if not key or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in key) or key in headers:
                    raise ValueError
                # Retain only needed fields; authorization and arbitrary tokens ignored.
                if key in ('user-agent', 'x-experiment-test', 'x-honeypot-client-ip'):
                    headers[key] = value.strip()
            agent = ''.join(c if 32 <= ord(c) < 127 else '?' for c in headers.get('user-agent', ''))[:256]
            is_test = hmac.compare_digest(headers.get('x-experiment-test', ''), self.test_marker)
            if self.trust_proxy:
                if not ipaddress.ip_address(peer_ip).is_loopback:
                    raise ValueError
                forwarded = str(ipaddress.ip_address(headers['x-honeypot-client-ip']))
                ip_hash = hmac.new(self.salt, forwarded.encode(), hashlib.sha256).hexdigest()
                if admitted:
                    admitted = self.allowed_ip(ip_hash)
            if not admitted:
                status = 429
            elif method not in ('GET', 'HEAD'):
                status = 405
            else:
                status = 200 if path in ROUTES else 404
            await self.reply(writer, status, method == 'HEAD')
        except (TimeoutError, asyncio.TimeoutError):
            status = 408 if admitted else 429
            await self.reply(writer, status)
        except (ValueError, UnicodeError, KeyError):
            if not admitted:
                status = 429
            await self.reply(writer, status)
        except (OSError, ConnectionError):
            status = 499
        finally:
            try:
                self.record(route, agent, lure, ip_hash, is_test, status)
            except sqlite3.Error:
                # Stop only this dedicated API rather than silently serve without logs.
                os._exit(75)
            finally:
                self.active -= 1
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), 1)
                except (TimeoutError, OSError):
                    pass

    async def reply(self, writer, status, head=False):
        names = {200: 'OK', 400: 'Bad Request', 404: 'Not Found', 405: 'Method Not Allowed',
                 408: 'Request Timeout', 429: 'Too Many Requests', 431: 'Request Header Fields Too Large'}
        body = BODY if status == 200 else b'{"ok":false,"data":"fictional-test-response"}\n'
        retry = 'Retry-After: 60\r\n' if status == 429 else ''
        writer.write((f'HTTP/1.1 {status} {names[status]}\r\nContent-Type: application/json\r\n'
                      f'Content-Length: {len(body)}\r\nConnection: close\r\nCache-Control: no-store\r\n'
                      f'{retry}\r\n').encode() + (b'' if head else body))
        try:
            await asyncio.wait_for(writer.drain(), 2)
        except (OSError, TimeoutError):
            pass

    def summary(self):
        rows = self.events()
        published = self.metadata().get('published_utc')
        baseline = timestamp(published) if published else None
        eligible = [r for r in rows if not r['is_test'] and
                    (baseline is None or timestamp(r['utc']) >= baseline)]
        now = time.time()
        def aggregate(items):
            first = items[0]['utc'] if items else None
            return {'total': len(items), 'new_last_minute': sum(timestamp(r['utc']) >= now-60 for r in items),
                    'unique_ip_hashes': len({r['ip_hash'] for r in items if r['ip_hash']}), 'first_request_utc': first,
                    'seconds_publication_to_first_request': timestamp(first)-baseline if first and baseline is not None else None,
                    'rate_limited': sum(r['status'] == 429 for r in items),
                    'unattributed_requests': sum(not r['ip_hash'] for r in items)}
        return {'generated_utc': utc(), 'published_utc': published, **aggregate(eligible),
                'test_requests': sum(r['is_test'] for r in rows),
                'prepublication_requests': sum(not r['is_test'] and baseline is not None and timestamp(r['utc']) < baseline for r in rows),
                'by_lure': {l: aggregate([r for r in eligible if r['lure_id'] == l]) for l in (*ROUTES.values(), 'unknown')},
                'github_traffic': 'separate source; not collected by API',
                'limitations': 'Counts HTTP requests logged by this API, not all connections, file views or downloads. Callers are not necessarily bots. IP hashes are not people.'}

    def export(self):
        summary = self.summary()
        for name, content in [('summary.json', json.dumps(summary, indent=2)), ('events.json', json.dumps(self.events(), indent=2))]:
            tmp = self.directory / (name + '.tmp')
            with open(tmp, 'w') as stream:
                os.chmod(tmp, 0o600)
                stream.write(content + '\n')
            os.replace(tmp, self.directory / name)
        rows = self.events()
        with open(self.directory / 'events.csv', 'w', newline='') as stream:
            os.chmod(self.directory / 'events.csv', 0o600)
            fields = ['id', 'utc', 'route', 'user_agent', 'lure_id', 'ip_hash', 'is_test', 'status']
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            for row in rows:
                writer.writerow({k: "'"+v if isinstance(v, str) and v.startswith(('=', '+', '-', '@', '\t', '\r')) else v for k,v in row.items()})
        with open(self.directory / 'summary.csv', 'w', newline='') as stream:
            os.chmod(self.directory / 'summary.csv', 0o600)
            fields = ['lure_id', 'total', 'new_last_minute', 'unique_ip_hashes', 'first_request_utc', 'seconds_publication_to_first_request', 'rate_limited', 'unattributed_requests']
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            for lure, values in summary['by_lure'].items():
                writer.writerow({'lure_id': lure, **values})
        return summary


async def serve(state, port):
    server = await asyncio.start_server(state.handle, '127.0.0.1', port, limit=8192, backlog=32)
    print(f'API listening on 127.0.0.1:{port}', flush=True)
    async with server:
        await server.serve_forever()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--state-dir', required=True)
    sub = parser.add_subparsers(dest='command', required=True)
    server = sub.add_parser('serve')
    server.add_argument('--port', type=int, default=8787)
    server.add_argument('--trust-loopback-proxy', action='store_true')
    sub.add_parser('export')
    sub.add_parser('report')
    pub = sub.add_parser('publication')
    pub.add_argument('--utc', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    state = State(args.state_dir, trust_proxy=getattr(args, 'trust_loopback_proxy', False))
    try:
        if args.command == 'serve':
            asyncio.run(serve(state, args.port))
        elif args.command == 'publication':
            state.set_publication(args.utc)
        else:
            result = state.export()
            if args.command == 'report':
                target = state.directory / 'final-report.md'
                target.write_text('# API honeypot final report\n\n' + json.dumps(result, indent=2) +
                                  '\n\nAPI requests and GitHub traffic are separate. Caller identity/automation is unproven. '
                                  'Deleting the repository does not revoke downloaded copies.\n')
                os.chmod(target, 0o600)
            print(json.dumps(result, indent=2))
    except KeyboardInterrupt:
        pass
    finally:
        state.db.close()


if __name__ == '__main__':
    main()

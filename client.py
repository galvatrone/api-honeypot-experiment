"""Fictional credentials, dedicated test API only; never call real providers."""
import argparse
import os
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler, ProxyHandler

FICTIONAL_KEY = 'hpx_live_254e7a12e28befa3265409edf01d0bd3e62110d29981553c'


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--marker-file', type=Path, required=True,
                        help='Private test marker on this machine; do not put it in Git')
    args = parser.parse_args()
    base = os.environ.get('HONEYPOT_BASE_URL', 'https://api-honeypot.example.invalid').rstrip('/')
    url = urlsplit(base)
    if url.scheme != 'https' and not (url.scheme == 'http' and url.hostname in ('127.0.0.1', 'localhost')):
        raise SystemExit('HTTPS required except loopback testing')
    if url.username or url.password or url.query or url.fragment:
        raise SystemExit('Plain dedicated endpoint required')
    headers = {'Authorization': 'Bearer '+FICTIONAL_KEY, 'User-Agent': 'honeypot-own-test/1.0',
               'X-Experiment-Test': args.marker_file.read_text().strip()}
    request = Request(base+'/v1/lures/python-client/status', headers=headers)
    # No redirects or inherited environment proxy to other systems.
    with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=5) as response:
        print(response.read(1024).decode())


if __name__ == '__main__':
    main()

# api-honeypot-experiment

Controlled experiment observing calls to a dedicated test API after public code publication. All example keys are random fictional credentials for this experiment, with no access to real services. This project never contacts real API providers, scans repositories, executes commands from requests or connects callers to other systems.

**Current status:** published on GitHub only at the owner’s request. The public API is not deployed; the `.invalid` address remains a placeholder. This publication alone cannot produce API observations.

Python 3.11+; standard library only. Two lure IDs: `example-env` in `.env.example` and `python-client` in `client.py`. Lure attribution uses the fixed URL route, not the submitted key. Authorization values are ignored and never saved. A call can therefore be made without a key and does not prove the key was extracted from GitHub.

## Local run

Keep private state outside this Git repository. From its root:

```sh
python -m unittest discover -s tests -v
python honeypot.py --state-dir ../api-honeypot-runtime serve --port 8787
```

In another terminal, send a marked test and start the local monitor:

```sh
HONEYPOT_BASE_URL=http://127.0.0.1:8787 python client.py --marker-file ../api-honeypot-runtime/test-marker
python monitor.py --state-dir ../api-honeypot-runtime
```

The client requires the private marker for every own test. It never follows redirects or uses environment proxies. The `.env.example` is a public example; no automatic dotenv loading is performed. Copy the URL to `HONEYPOT_BASE_URL` explicitly. Never use a real key.

## API and privacy

- `GET`/`HEAD /v1/lures/example-env/status` and `/v1/lures/python-client/status`: fixed fictional JSON. Other routes get a fixed 404; other methods get 405. No request execution, body processing, upstream API calls or outbound network code in the server.
- Loopback binding, 32 simultaneous HTTP handlers, 8 KiB parsing buffer, 3 second header deadline, 2 second write deadline. Each connection closes after one request.
- 30 requests per IP hash per fixed 60 second window; 300 globally (including malformed HTTP). Excess parsed requests return 429 and remain counted. Fixed windows can permit bursts at the boundary; these are observation limits, not DDoS protection.
- SQLite events: UTC timestamp, normalized route, up to 256 printable ASCII User-Agent characters, lure ID, HMAC-SHA256 IP hash, own-test flag and response status. Unknown paths become `/unknown`, incomplete requests `/unparsed`; queries, Authorization and bodies are discarded. User-Agent is untrusted attacker supplied text; CSV formula prefixes are escaped and terminal controls sanitized.
- A fresh private random salt and test marker are generated in the state directory (0700; files 0600). Stable hashes are comparable only within this experiment and are not identities. Submitted private markers are compared, never stored as events.
- Default mode ignores forwarding headers. `--trust-loopback-proxy` requires a trusted loopback reverse proxy that overwrites `X-Honeypot-Client-IP` with its socket client address. Do not enable it behind an unverified proxy or expose the backend directly.
- Connection cap, malformed TLS or proxy-rejected traffic may never reach the API and is not fully visible. Events are logged after response handling; disk failure can cause gaps. SQLite has an approximately 128 MiB main-database cap (WAL files add overhead); on a database write failure this dedicated API exits with status 75 and the example service does not restart it. Keep sufficient private disk space. Errors without a validated client address in proxy mode have an empty hash and are counted as unattributed, excluded from unique-IP totals.

## Monitor and exports

`monitor.py` updates every 60 seconds. It prints total requests, requests during the rolling last 60 seconds, unique IP hashes, time from publication to first observed request, rate rejections and statistics for each lure. Own tests are shown separately and excluded from observation totals and first-request timing. Prepublication events are also separate once a baseline exists. Before a baseline is recorded, observations are provisional and first-request delay is null.

```sh
python monitor.py --state-dir ../api-honeypot-runtime --once
python honeypot.py --state-dir ../api-honeypot-runtime export
```

Private output: `summary.json`, `summary.csv`, `events.json`, `events.csv`. The raw event export retains the `is_test` label for audit; summary exports exclude tests. Never commit or publish them. Running `export` itself makes no API request.

## HTTPS deployment and publication

Infrastructure selection is pending. The `.invalid` endpoint is a placeholder, not a running public API. Before a future publication with a working public API:

1. Select an owned dedicated HTTPS endpoint, TLS termination and host. Use the example nginx vhost and dedicated service in `docs/` only after replacing paths/domain. Keep state outside Git. Existing projects must remain unchanged.
2. Disable raw request/access logs at every infrastructure layer, including any CDN/provider. Do not enable IP attribution through a CDN until its trusted address handling and data retention have been verified. The nginx example assumes a direct connection to the TLS proxy.
3. Start this dedicated backend, validate TLS and both lure routes using the private own-test marker. Ensure fixed replies, accurate hashed client attribution, no proxy raw-IP logs and limits. The template itself has not been deployed or tested with nginx.
4. Replace the `.invalid` base URL in `.env.example` and the client's default with the verified owned HTTPS endpoint. Review an explicit publication file allowlist. Do not publish state, SSH details or service secrets.
5. Record `published_utc` in private state immediately before the first public push using `python honeypot.py --state-dir STATE publication --utc YYYY-MM-DDTHH:MM:SSZ`. Record push completion UTC separately in a private lifecycle record. Timing from this baseline has uncertainty equal to the push interval. Never backfill the baseline after monitoring starts without recording the uncertainty.
6. Create only `galvatrone/api-honeypot-experiment` and push the reviewed experiment files. Keep its exact name, service identity and endpoint in a private lifecycle record for shutdown. Check owner/name before any deletion. An existing repository with this name must not be overwritten.

## Interpretation and GitHub traffic

An API request shows that someone reached this API. It does not establish automation, origin from GitHub, a secret scanner, or use of an extracted key. No requests can also mean a scanner ignored obviously fictional examples. Unique hashes are not unique users (NAT, changing IPs). Publication metadata and unrelated web crawlers can also produce traffic.

GitHub repository views/clones are a separate aggregate dataset with its own retention and permission limits. The API monitor cannot see all file views, code copies or downloads. Optional GitHub traffic snapshots must be stored privately and labeled separately; they are not collected automatically here and must not be added to API request counts.

## Finish after explicit request

When the owner says **«заверши эксперимент»**, the operator must:

1. Save a preliminary local export, stop only the recorded experiment service and remove/disable only its dedicated public HTTPS route. Verify it no longer returns the experiment response; mark any shutdown probes as own tests.
2. Export again after shutdown so final events are included: `python honeypot.py --state-dir STATE report`. Preserve `final-report.md`, JSON/CSV, database and lifecycle timestamps locally. For a remote host, retrieve the private results before host cleanup. Record publication interval, shutdown UTC, methodology, limitations and any separate GitHub traffic snapshot.
3. Confirm the exact repository is `galvatrone/api-honeypot-experiment`; delete only it using `gh repo delete galvatrone/api-honeypot-experiment --yes`, and verify it is no longer public. The current GitHub credential lacks `delete_repo`; deletion may require an owner-approved scope refresh at that time.
4. Stop only this experiment's local monitor. Retain local results and code. Do not remove any other repository or service.

Deletion does **not** revoke already downloaded copies. There is no scheduled automatic cleanup or implicit authorization to stop other projects.

Reference: [nginx proxy directives](https://nginx.org/en/docs/http/ngx_http_proxy_module.html), [nginx request limits/timeouts](https://nginx.org/en/docs/http/ngx_http_core_module.html), [GitHub traffic API](https://docs.github.com/en/rest/metrics/traffic).

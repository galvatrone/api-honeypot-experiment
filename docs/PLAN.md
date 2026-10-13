# API honeypot experiment

Purpose: observe calls to a dedicated public HTTPS API after publishing fictional credentials in a new GitHub repository. No real provider APIs, external scanning, command execution, proxying or integrations.

Implementation plan (native execution, authorized by the user's detailed request):
1. Write behavioral tests for bounded HTTP handling, privacy, rate limiting, test exclusion and aggregates. Observe failures before implementation.
2. Implement standard-library asyncio HTTP service, local SQLite events and local monitor (60 second refresh, JSON/CSV exports).
3. Add fictional example credentials/client, deployment and termination instructions. Runtime secrets, logs, database and exports live outside the repository.
4. Run complete tests and local smoke checks. Discover user's HTTPS infrastructure; configure only this experiment, then verify marked requests through HTTPS.
5. Publish only an explicit reviewed file allowlist to galvatrone/api-honeypot-experiment. Record publication UTC locally around the push, including measurement uncertainty.
6. On explicit 'заверши эксперимент': export/report locally, stop this experiment's public API and delete only the recorded experiment repository. Retain local results. Downloaded copies cannot be recalled.

Design: bind API to loopback; HTTPS reverse proxy must disable access/error request logs, overwrite X-Honeypot-Client-IP with its socket client address, enforce request limits and timeouts. Backend trusts that header only with an explicitly configured loopback proxy. HMAC-SHA256 IP pseudonyms with private per-experiment salt. Known routes only in logs; unknown routes collapse to /unknown. Do not read bodies or save headers other than bounded sanitized User-Agent. No authorization values saved. Test marker is a private random value, never an example key.

Review focus: forwarding spoofing; unknown paths/query tokens; rate-rejected traffic; slow/oversized requests; timestamp baseline and test exclusion. All belong in tests. GitHub traffic is a separate optional manual snapshot, not API telemetry or proof of file-level visibility. API callers cannot reliably be classified as bots.

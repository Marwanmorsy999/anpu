# Benchmark fixture

Deliberately vulnerable local target for `anpu bench` ground truth
(see [`ground-truth.yml`](ground-truth.yml) for the machine-readable
signal list and [`../../docs/benchmark.md`](../../docs/benchmark.md)
for published results).

## Run it

With Docker (same image CI uses):

```sh
docker compose -f tests/bench/docker-compose.yml up -d
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8901/
```

Without Docker (identical server, identical signals):

```sh
python tests/bench/server.py 8901
```

Then:

```sh
go run ./cmd/anpu bench --target http://127.0.0.1:8901
```

Tear down with `docker compose -f tests/bench/docker-compose.yml down`.
The fixture binds loopback only and serves fake secrets (`server.py`
`FAKE_ENV`) — safe to run anywhere, nothing leaves the machine.
(Direct `python server.py` runs bind `127.0.0.1`; under compose the
container listens on `0.0.0.0` while the port is published on host
loopback only — Docker forwards host ports via container eth0, so a
loopback bind inside the container would refuse them.)

## What's planted

| Path | Signal | Expected detector |
| ---- | ------ | ----------------- |
| `/` (no security headers) | `weak-headers` | headers posture (`safe` + `advanced`) |
| `/.env` (fake `KEY=` secrets) | `exposed-env` | exposedconfig (`advanced`) |
| `/backup.zip` (generated ZIP) | `backup-zip` | backup scanner (`advanced`) |
| `/search?q=` (raw reflection) | `reflected-xss` | dalfox / active XSS (`advanced`) |
| `/go?url=` (302 to absolute URL) | `open-redirect` | redirectpack / active redirect (`advanced`) |

The homepage links every vector and carries a GET search form plus a
POST comment form, so crawlers discover the parameters without any
special configuration.

## Design rules for changes

1. **Calibrate before claiming.** Any new signal must be verified with
   real `safe` + `advanced` scans before it lands in `ground-truth.yml`
   with `hit`. A planted signal ANPU cannot detect is a `miss` with a
   rationale — never silently dropped from the file.
2. **Fake data only.** No real credentials, keys, or PII anywhere in
   the fixture. Ever.
3. **Loopback only.** The server binds `127.0.0.1`; compose publishes
   the port on loopback. The harness refuses to auto-allow non-loopback
   targets.

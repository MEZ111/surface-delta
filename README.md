# SurfaceDelta

Attack-surface drift detection for security teams that need to know **what
changed**, not just what a scanner found.

SurfaceDelta compares two JSONL service snapshots and prioritizes new exposure,
TLS regressions, public-access changes, and software fingerprint changes. Its
scoring policy is explicit and deterministic, so every alert can be explained.
Reports carry SHA-256 digests of both snapshots, tying every decision to the
exact evidence that produced it.

## Signals

| Change | Evidence | Risk effect |
| --- | --- | ---: |
| Service opened | host + port absent from baseline | port policy + exposure |
| TLS removed | same service changed from TLS to plaintext | +50 |
| Became public | same service changed from private to public | +40 |
| Fingerprint changed | product or version changed | +15 |

## Install

```bash
git clone https://github.com/MEZ111/surface-delta.git
cd surface-delta
python3 -m pip install .
```

## Run

```bash
surface-delta tests/before.jsonl tests/after.jsonl -o delta.md
surface-delta tests/before.jsonl tests/after.jsonl --json
surface-delta tests/before.jsonl tests/after.jsonl --fail-risk 70
surface-delta tests/before.jsonl tests/after.jsonl --policy examples/policy.json
```

`--fail-risk` makes the command useful as a deployment gate: it exits with code
1 when a change meets the chosen risk threshold.

## Input

One JSON object per service:

```json
{"asset":"cache.example.test","port":6379,"protocol":"tcp","service":"redis","product":"redis","version":"7","tls":false,"public":true}
```

## Verification

```bash
PYTHONPATH=src python3 -m unittest -v tests/test_surface_delta.py
```

Five tests cover exposed database prioritization, TLS regression detection,
custom policy weights, snapshot provenance, and invalid input. GitHub Actions
installs the command and verifies the full sample.

## Boundaries

SurfaceDelta does not scan hosts and does not claim a vulnerability exists. It
compares supplied evidence and explains which changes deserve review. Use only
data collected under an authorized security scope.

## License

MIT

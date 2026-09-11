#!/usr/bin/env python3
"""Detect meaningful attack-surface drift between two JSONL snapshots."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


DEFAULT_WEIGHTS = {21: 45, 22: 25, 23: 70, 25: 35, 53: 15, 80: 10,
                   443: 5, 445: 65, 1433: 60, 2375: 70, 3306: 60,
                   3389: 65, 5432: 60, 6379: 70, 9200: 45, 27017: 70}


@dataclass(frozen=True)
class Service:
    asset: str
    port: int
    protocol: str
    service: str
    product: str
    version: str
    tls: bool
    public: bool

    @property
    def key(self) -> tuple[str, int, str]:
        return self.asset, self.port, self.protocol


@dataclass(frozen=True)
class Change:
    kind: str
    asset: str
    port: int
    protocol: str
    risk: int
    before: dict | None
    after: dict | None
    reasons: tuple[str, ...]


def parse_service(record: dict) -> Service:
    asset = str(record.get("asset") or record.get("host") or "").strip().lower().rstrip(".")
    if not asset:
        raise ValueError("missing asset")
    try:
        port = int(record["port"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("invalid port") from exc
    if not 1 <= port <= 65535:
        raise ValueError("port outside 1..65535")
    return Service(
        asset=asset,
        port=port,
        protocol=str(record.get("protocol") or "tcp").lower(),
        service=str(record.get("service") or "unknown").lower(),
        product=str(record.get("product") or "unknown"),
        version=str(record.get("version") or "unknown"),
        tls=bool(record.get("tls", False)),
        public=bool(record.get("public", True)),
    )


def load_snapshot(lines: Iterable[str]) -> tuple[dict[tuple[str, int, str], Service], list[str]]:
    services, errors = {}, []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError("expected object")
            service = parse_service(value)
            services[service.key] = service
        except (json.JSONDecodeError, ValueError) as exc:
            errors.append(f"line {number}: {exc}")
    return services, errors


def score_new(service: Service, weights: dict[int, int]) -> tuple[int, tuple[str, ...]]:
    score, reasons = weights.get(service.port, 20), ["new listening service"]
    if service.public:
        score += 15
        reasons.append("publicly reachable")
    if not service.tls and service.port not in {22, 53, 80}:
        score += 10
        reasons.append("transport not marked TLS")
    if service.version not in {"", "unknown"}:
        score += 5
        reasons.append("version exposed")
    return min(score, 100), tuple(reasons)


def compare(old: dict, new: dict, weights: dict[int, int] | None = None) -> list[Change]:
    weights = weights or DEFAULT_WEIGHTS
    changes: list[Change] = []
    for key in sorted(new.keys() - old.keys()):
        service = new[key]
        risk, reasons = score_new(service, weights)
        changes.append(Change("opened", *key, risk, None, asdict(service), reasons))
    for key in sorted(old.keys() - new.keys()):
        service = old[key]
        changes.append(Change("closed", *key, 0, asdict(service), None, ("service no longer observed",)))
    for key in sorted(old.keys() & new.keys()):
        before, after = old[key], new[key]
        if before == after:
            continue
        reasons, score = [], 10
        if before.tls and not after.tls:
            reasons.append("TLS removed")
            score += 50
        if not before.public and after.public:
            reasons.append("became publicly reachable")
            score += 40
        if (before.product, before.version) != (after.product, after.version):
            reasons.append("software fingerprint changed")
            score += 15
        if before.service != after.service:
            reasons.append("service classification changed")
            score += 10
        changes.append(Change("changed", *key, min(score, 100), asdict(before), asdict(after), tuple(reasons)))
    return sorted(changes, key=lambda x: (-x.risk, x.asset, x.port))


def markdown(changes: list[Change], errors: list[str]) -> str:
    lines = ["# Surface Delta", "", f"**Changes:** {len(changes)} · **Rejected records:** {len(errors)}", "",
             "| Risk | Change | Asset | Port | Reasons |", "| ---: | --- | --- | ---: | --- |"]
    for change in changes:
        reasons = "; ".join(change.reasons).replace("|", "\\|")
        lines.append(f"| {change.risk} | {change.kind} | {change.asset} | {change.port}/{change.protocol} | {reasons} |")
    if errors:
        lines += ["", "## Rejected records", ""] + [f"- {e}" for e in errors]
    lines += ["", "> Drift is a review signal, not proof of vulnerability. Confirm authorization and validate manually.", ""]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--fail-risk", type=int, default=101, metavar="SCORE")
    args = parser.parse_args()
    with args.before.open(encoding="utf-8") as file:
        before, before_errors = load_snapshot(file)
    with args.after.open(encoding="utf-8") as file:
        after, after_errors = load_snapshot(file)
    errors = before_errors + after_errors
    changes = compare(before, after)
    output = json.dumps({"changes": [asdict(c) for c in changes], "errors": errors}, indent=2) if args.json else markdown(changes, errors)
    if args.output:
        args.output.write_text(output, encoding="utf-8")
    else:
        print(output)
    return 1 if any(change.risk >= args.fail_risk for change in changes) else 0


if __name__ == "__main__":
    raise SystemExit(main())

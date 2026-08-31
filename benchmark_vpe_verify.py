#!/usr/bin/env python3
"""
P5.1: VPE verification benchmark.

Measures vpe_verify() latency for 1KB, 10KB, 100KB envelopes with
breakdown: JSON parse, structural checks, canonical JSON rebuild,
signature verification.

Target: <5ms for 1KB, <20ms for 100KB.

Usage: uv run python benchmark_vpe_verify.py
"""

import hashlib
import json
import secrets
import statistics
import time
from collections import OrderedDict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from seal.core import VPE_VERSION, generate_key_pair, _canonical_json, _load_public_key

# ── Synthetic envelope generation ──────────────────────────────────────────

def make_envelope(target_bytes: int, *, private_key: bytes) -> str:
    """Build a signed VPE envelope whose JSON representation is ~target_bytes."""
    # Start with minimal fields, pad prompt to hit target size.
    padding = "A" * max(0, target_bytes - 500)  # 500B baseline overhead

    sk = Ed25519PrivateKey.from_private_bytes(private_key)

    envelope = OrderedDict()
    envelope["vpe_version"] = VPE_VERSION
    envelope["prompt"] = f"execute the following analysis: {padding}"
    envelope["scope"] = {
        "allowed_tools": ["read", "write", "search", "execute"],
        "max_tokens": 8192,
        "max_cost": 0.05,
    }
    envelope["issuer"] = "user:rez"
    envelope["audience"] = "agent:hermes-seal"
    envelope["doc_sha256"] = hashlib.sha256(
        envelope["prompt"].encode()
    ).hexdigest()
    envelope["ttl_seconds"] = 300
    envelope["nonce"] = secrets.token_hex(16)
    envelope["counter"] = 1
    envelope["signature"] = ""

    canon = _canonical_json(envelope)
    signature = sk.sign(canon)
    envelope["signature"] = signature.hex()

    encoded = json.dumps(envelope, separators=(",", ":"))
    actual_size = len(encoded)

    # Iteratively adjust padding to hit target size (±5%)
    if actual_size < target_bytes * 0.95 or actual_size > target_bytes * 1.05:
        delta = target_bytes - actual_size
        pad_needed = max(0, len(padding) + delta)
        padding = "A" * pad_needed
        envelope["prompt"] = f"execute the following analysis: {padding}"
        envelope["doc_sha256"] = hashlib.sha256(
            envelope["prompt"].encode()
        ).hexdigest()
        envelope["signature"] = ""
        canon = _canonical_json(envelope)
        signature = sk.sign(canon)
        envelope["signature"] = signature.hex()
        encoded = json.dumps(envelope, separators=(",", ":"))

    return encoded


# ── Benchmarked verification with phase timing ─────────────────────────────

def verify_with_breakdown(
    envelope_str: str, *, public_key: bytes
) -> dict:
    """
    Run vpe_verify, instrumenting each phase.

    Returns {valid, reason} and wall-clock times for each phase (ns).
    """
    phases = {}

    # Phase 1: JSON parse
    t0 = time.perf_counter_ns()
    try:
        envelope = json.loads(envelope_str)
    except (json.JSONDecodeError, ValueError) as exc:
        phases["parse_ns"] = time.perf_counter_ns() - t0
        return {"valid": False, "reason": f"invalid_json: {exc}", "phases": phases}
    phases["parse_ns"] = time.perf_counter_ns() - t0

    t1 = time.perf_counter_ns()

    if not isinstance(envelope, dict):
        phases["structural_checks_ns"] = time.perf_counter_ns() - t1
        return {"valid": False, "reason": "invalid_json: not a dict", "phases": phases}

    version = envelope.get("vpe_version", "")
    if version != VPE_VERSION:
        phases["structural_checks_ns"] = time.perf_counter_ns() - t1
        return {"valid": False, "reason": f"unsupported_version: {version}", "phases": phases}

    sig_hex = envelope.get("signature", "")
    if not sig_hex:
        phases["structural_checks_ns"] = time.perf_counter_ns() - t1
        return {"valid": False, "reason": "missing_signature", "phases": phases}

    scope = envelope.get("scope", {})
    if not isinstance(scope, dict):
        phases["structural_checks_ns"] = time.perf_counter_ns() - t1
        return {"valid": False, "reason": "scope_not_dict", "phases": phases}

    nonce = envelope.get("nonce", "")
    if not isinstance(nonce, str) or nonce == "":
        phases["structural_checks_ns"] = time.perf_counter_ns() - t1
        return {"valid": False, "reason": "missing_or_empty_nonce", "phases": phases}

    counter = envelope.get("counter")
    if counter is not None and not isinstance(counter, int):
        phases["structural_checks_ns"] = time.perf_counter_ns() - t1
        return {"valid": False, "reason": "counter_not_integer", "phases": phases}

    ttl = envelope.get("ttl_seconds", 0)
    if not isinstance(ttl, int):
        phases["structural_checks_ns"] = time.perf_counter_ns() - t1
        return {"valid": False, "reason": "ttl_not_integer", "phases": phases}

    phases["structural_checks_ns"] = time.perf_counter_ns() - t1

    # Phase 3: Canonical JSON rebuild (signature verification prep)
    t2 = time.perf_counter_ns()
    verify_envelope = dict(envelope)
    verify_envelope["signature"] = ""
    canon = _canonical_json(verify_envelope)
    phases["canonical_json_ns"] = time.perf_counter_ns() - t2

    # Phase 4: Signature decode
    t3 = time.perf_counter_ns()
    try:
        sig_bytes = bytes.fromhex(sig_hex)
    except ValueError:
        phases["signature_decode_ns"] = time.perf_counter_ns() - t3
        return {"valid": False, "reason": "invalid_signature_encoding", "phases": phases}
    phases["signature_decode_ns"] = time.perf_counter_ns() - t3

    # Phase 5: Ed25519 verify
    t4 = time.perf_counter_ns()
    pk = _load_public_key(public_key)
    try:
        pk.verify(sig_bytes, canon)
    except InvalidSignature:
        phases["ed25519_verify_ns"] = time.perf_counter_ns() - t4
        return {"valid": False, "reason": "signature_mismatch", "phases": phases}
    phases["ed25519_verify_ns"] = time.perf_counter_ns() - t4

    # Phase 6: TTL expiry note (pass-through in v1.0)
    t5 = time.perf_counter_ns()
    if ttl > 0:
        pass  # caller's responsibility in v1.0
    phases["ttl_check_ns"] = time.perf_counter_ns() - t5

    total_patched = sum(phases.values())
    phases["total_ns"] = total_patched

    return {"valid": True, "reason": "ok", "phases": phases}


# ── Reference: unmodified vpe_verify total timing ──────────────────────────

from seal.core import vpe_verify as real_vpe_verify


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    SIZES = [
        ("1KB", 1_000),
        ("10KB", 10_000),
        ("100KB", 100_000),
    ]
    ITERATIONS = 100

    print("=" * 78)
    print("P5.1: VPE Verification Benchmark")
    print(f"Iterations per size: {ITERATIONS}")
    print("=" * 78)

    keys = generate_key_pair()

    for label, target_size in SIZES:
        print(f"\n── {label} envelopes (target ~{target_size:,} bytes) ──\n")

        # Generate a single envelope of the right size
        envelope = make_envelope(target_size, private_key=keys["private_key"])
        actual_size = len(envelope)
        print(f"  Actual envelope size: {actual_size:,} bytes")
        print()

        # 1) Full unmodified vpe_verify timing
        raw_times = []
        for _ in range(ITERATIONS):
            t0 = time.perf_counter_ns()
            result = real_vpe_verify(envelope, public_key=keys["public_key"])
            dt = time.perf_counter_ns() - t0
            raw_times.append(dt)

        assert result["valid"], f"Verification failed: {result['reason']}"

        avg_raw_ms = statistics.mean(raw_times) / 1_000_000
        min_raw_ms = min(raw_times) / 1_000_000
        max_raw_ms = max(raw_times) / 1_000_000
        stdev_raw_ms = statistics.stdev(raw_times) / 1_000_000

        print(f"  vpe_verify (unmodified, {ITERATIONS} runs):")
        print(f"    avg: {avg_raw_ms:.4f} ms")
        print(f"    min: {min_raw_ms:.4f} ms")
        print(f"    max: {max_raw_ms:.4f} ms")
        print(f"    std: {stdev_raw_ms:.4f} ms")
        print(f"    envelope_size/avg_time: {actual_size / (avg_raw_ms/1000):,.0f} bytes/sec")

        # 2) Phase breakdown
        phase_timings = {
            "parse": [],
            "structural_checks": [],
            "canonical_json": [],
            "signature_decode": [],
            "ed25519_verify": [],
            "ttl_check": [],
        }

        for _ in range(ITERATIONS):
            result = verify_with_breakdown(envelope, public_key=keys["public_key"])
            assert result["valid"]
            phases = result["phases"]
            phase_timings["parse"].append(phases["parse_ns"])
            phase_timings["structural_checks"].append(phases["structural_checks_ns"])
            phase_timings["canonical_json"].append(phases["canonical_json_ns"])
            phase_timings["signature_decode"].append(phases["signature_decode_ns"])
            phase_timings["ed25519_verify"].append(phases["ed25519_verify_ns"])
            phase_timings["ttl_check"].append(phases["ttl_check_ns"])

        total_avg = 0
        print(f"  Phase breakdown ({ITERATIONS} runs, avg):")
        for phase_name, timings in phase_timings.items():
            avg_ns = statistics.mean(timings)
            avg_ms = avg_ns / 1_000_000
            pct = avg_ns / statistics.mean(raw_times) * 100
            total_avg += avg_ns
            print(f"    {phase_name:25s}  {avg_ms:8.4f} ms  ({pct:5.1f}%)")

        # Overhead check: sum of phases vs raw measurement
        overhead = statistics.mean(raw_times) - total_avg
        overhead_ms = overhead / 1_000_000
        overhead_pct = overhead / statistics.mean(raw_times) * 100
        print(f"    {'instrumentation overhead':25s}  {overhead_ms:8.4f} ms  ({overhead_pct:5.1f}%)")

        # Pass/fail vs targets
        if target_size == 1_000:
            target_ms = 5.0
        elif target_size == 10_000:
            target_ms = 10.0  # interpolated
        else:
            target_ms = 20.0

        if avg_raw_ms < target_ms:
            print(f"\n  ✓ PASS: {avg_raw_ms:.2f}ms < {target_ms}ms target")
        else:
            print(f"\n  ✗ FAIL: {avg_raw_ms:.2f}ms >= {target_ms}ms target")

    print("\n" + "=" * 78)
    print("Benchmark complete.")
    print("=" * 78)


if __name__ == "__main__":
    main()

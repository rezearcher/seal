#!/usr/bin/env python3
"""
P5.3: Envelope size optimisation benchmark.

Measures size savings and parse-time overhead for compact vs standard
envelopes at various prompt sizes.

Target: <300B overhead for compact Ed25519 envelopes.

Usage: uv run python benchmark_envelope_size.py
"""

import json
import statistics
import time

from seal.core import (
    VPE_VERSION,
    generate_key_pair,
    vpe_sign,
    vpe_sign_hmac,
    vpe_verify,
    vpe_verify_hmac,
)

# ── Test parameters ──────────────────────────────────────────────────────────

# Prompt lengths to test (bytes)
PROMPT_SIZES = [1, 10, 50, 200, 1000]

ITERATIONS = 500  # parse-time iterations per prompt size


# ── Size measurement ─────────────────────────────────────────────────────────

def measure_sizes(keys) -> list[dict]:
    """Return list of {prompt_len, std_size, compact_size, overhead_std,
    overhead_compact} dicts."""
    results = []
    for plen in PROMPT_SIZES:
        prompt = "A" * plen

        std = vpe_sign(prompt, private_key=keys["private_key"])
        cpt = vpe_sign(prompt, compact=True, private_key=keys["private_key"])

        results.append({
            "prompt_len": plen,
            "std_size": len(std),
            "compact_size": len(cpt),
            "std_overhead": len(std) - plen,
            "compact_overhead": len(cpt) - plen,
            "savings": ((len(std) - len(cpt)) / len(std)) * 100,
            "std_envelope": std,
            "compact_envelope": cpt,
        })
    return results


# ── Parse-time benchmark ─────────────────────────────────────────────────────

def benchmark_parse(envelope_str: str, iterations: int) -> tuple[float, float]:
    """Time json.loads over *iterations* iterations.

    Returns (avg_ms, std_ms).
    """
    times = []
    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        _ = json.loads(envelope_str)
        dt = time.perf_counter_ns() - t0
        times.append(dt)
    avg_ns = statistics.mean(times)
    stdev_ns = statistics.stdev(times) if len(times) > 1 else 0
    return avg_ns / 1_000_000, stdev_ns / 1_000_000


def benchmark_verify(envelope_str: str, *, public_key: bytes,
                     iterations: int) -> tuple[float, float, dict]:
    """Time vpe_verify over *iterations* iterations.

    Returns (avg_ms, std_ms, last_result).
    """
    times = []
    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        result = vpe_verify(envelope_str, public_key=public_key)
        dt = time.perf_counter_ns() - t0
        times.append(dt)
    avg_ns = statistics.mean(times)
    stdev_ns = statistics.stdev(times) if len(times) > 1 else 0
    return avg_ns / 1_000_000, stdev_ns / 1_000_000, result


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("=" * 78)
    print("P5.3: Envelope Size Optimisation Benchmark")
    print(f"Iterations per measurement: {ITERATIONS}")
    print("=" * 78)

    keys = generate_key_pair()

    # ── 1. Size comparison ────────────────────────────────────────────────
    print("\n── 1. Size comparison: standard vs compact ──\n")
    print(f"  {'Prompt':>10s} | {'Std':>8s} | {'Compact':>8s} | "
          f"{'Std O/H':>8s} | {'Cpt O/H':>8s} | {'Saved':>6s}")
    print(f"  {'─'*10}-+-{'─'*8}-+-{'─'*8}-+-{'─'*8}-+-{'─'*8}-+-{'─'*6}")

    sizes = measure_sizes(keys)
    for r in sizes:
        print(f"  {r['prompt_len']:>5d} B    | {r['std_size']:>5d} B | "
              f"{r['compact_size']:>5d} B | {r['std_overhead']:>5d} B | "
              f"{r['compact_overhead']:>5d} B | {r['savings']:>4.0f}%")

    # Check target
    min_prompt = sizes[0]
    pass_target = min_prompt["compact_overhead"] < 300
    status = "PASS" if pass_target else "FAIL"
    print(f"\n  Target: <300B overhead → {status} "
          f"(min overhead = {min_prompt['compact_overhead']} B)")

    # ── 2. HMAC size comparison ──────────────────────────────────────────
    print("\n── 2. HMAC size comparison (bonus) ──\n")
    secret = b"benchmark-secret-32-bytes-for-envelope-size!"
    print(f"  {'Prompt':>10s} | {'Std':>8s} | {'Compact':>8s} | "
          f"{'Std O/H':>8s} | {'Cpt O/H':>8s}")
    print(f"  {'─'*10}-+-{'─'*8}-+-{'─'*8}-+-{'─'*8}-+-{'─'*8}")

    for plen in PROMPT_SIZES:
        prompt = "A" * plen
        std = vpe_sign_hmac(prompt, shared_secret=secret)
        cpt = vpe_sign_hmac(prompt, compact=True, shared_secret=secret)
        print(f"  {plen:>5d} B    | {len(std):>5d} B | "
              f"{len(cpt):>5d} B | {len(std)-plen:>5d} B | "
              f"{len(cpt)-plen:>5d} B")

    # ── 3. Parse time comparison ─────────────────────────────────────────
    print("\n── 3. Parse time: standard vs compact ──\n")
    plen_show = 50
    prompt = "A" * plen_show
    std_env = vpe_sign(prompt, private_key=keys["private_key"])
    cpt_env = vpe_sign(prompt, compact=True, private_key=keys["private_key"])

    std_parse_avg, std_parse_std = benchmark_parse(std_env, ITERATIONS)
    cpt_parse_avg, cpt_parse_std = benchmark_parse(cpt_env, ITERATIONS)

    print(f"  Prompt: {plen_show} B")
    print(f"  Standard envelope:  {len(std_env):>4d} B  —  "
          f"parse: {std_parse_avg:.4f} ± {std_parse_std:.4f} ms")
    print(f"  Compact envelope:   {len(cpt_env):>4d} B  —  "
          f"parse: {cpt_parse_avg:.4f} ± {cpt_parse_std:.4f} ms")
    if cpt_parse_avg < std_parse_avg:
        speedup = (std_parse_avg - cpt_parse_avg) / std_parse_avg * 100
        print(f"  → Compact parse is {speedup:.1f}% faster")
    else:
        slowdown = (cpt_parse_avg - std_parse_avg) / std_parse_avg * 100
        print(f"  → Compact parse is {slowdown:.1f}% slower")

    # ── 4. Verify time comparison ─────────────────────────────────────────
    print("\n── 4. Verify time: standard vs compact ──\n")

    std_ver_avg, std_ver_std, _ = benchmark_verify(
        std_env, public_key=keys["public_key"], iterations=ITERATIONS)
    cpt_ver_avg, cpt_ver_std, _ = benchmark_verify(
        cpt_env, public_key=keys["public_key"], iterations=ITERATIONS)

    print(f"  Standard verify:  {std_ver_avg:.4f} ± {std_ver_std:.4f} ms")
    print(f"  Compact verify:   {cpt_ver_avg:.4f} ± {cpt_ver_std:.4f} ms")

    if cpt_ver_avg < std_ver_avg:
        speedup = (std_ver_avg - cpt_ver_avg) / std_ver_avg * 100
        print(f"  → Compact verify is {speedup:.1f}% faster")
    else:
        diff = (cpt_ver_avg - std_ver_avg) / std_ver_avg * 100
        print(f"  → Difference: {diff:+.1f}% (within noise)" if abs(diff) < 5
              else f"  → Compact verify is {abs(diff):.1f}% slower")

    # ── 5. Stipping analysis ──────────────────────────────────────────────
    print("\n── 5. Stripping analysis for minimal envelope ──\n")
    cpt_data = json.loads(min_prompt["compact_envelope"])
    kept = list(cpt_data.keys())
    stripped = [k for k in [
        "vpe_version", "scope", "issuer", "audience",
        "doc_sha256", "ttl_seconds", "counter", "cert_chain"
    ] if k not in kept]
    print(f"  Kept fields:    {', '.join(kept)}")
    print(f"  Stripped fields: {', '.join(stripped) if stripped else 'none'}")
    print(f"  Compact raw:    {min_prompt['compact_envelope']}")
    print(f"  Standard raw:   {min_prompt['std_envelope'][:80]}...")

    # ── Summary ───────────────────────────────────────────────────────────
    print("\n" + "=" * 78)
    print("Benchmark complete.")
    print(f"  Ed25519 compact overhead: {min_prompt['compact_overhead']} B "
          f"(target <300 B: {'PASS' if pass_target else 'FAIL'})")
    print(f"  Savings on {min_prompt['prompt_len']}-B prompt: "
          f"{min_prompt['std_size'] - min_prompt['compact_size']} B "
          f"({min_prompt['savings']:.0f}%)")
    print("=" * 78)


if __name__ == "__main__":
    main()

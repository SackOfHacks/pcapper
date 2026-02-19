from __future__ import annotations

import argparse
import os
import random
import time

from .utils import decode_payload


def _make_payloads(total: int, unique: int, size: int) -> list[bytes]:
    random.seed(1337)
    base = [
        os.urandom(size)
        for _ in range(max(1, unique))
    ]
    payloads = [base[i % len(base)] for i in range(total)]
    random.shuffle(payloads)
    return payloads


def _bench_decode(payloads: list[bytes], rounds: int, use_cache: bool) -> float:
    start = time.perf_counter()
    for _ in range(rounds):
        for payload in payloads:
            decode_payload(payload, encoding="latin-1", cache=use_cache)
    end = time.perf_counter()
    return end - start


def main() -> int:
    parser = argparse.ArgumentParser(description="PCAPPER decode cache micro-benchmark")
    parser.add_argument("--total", type=int, default=20000, help="Total payloads per round")
    parser.add_argument("--unique", type=int, default=200, help="Unique payload count")
    parser.add_argument("--size", type=int, default=256, help="Payload size in bytes")
    parser.add_argument("--rounds", type=int, default=3, help="Benchmark rounds")
    args = parser.parse_args()

    payloads = _make_payloads(args.total, args.unique, args.size)

    t_nocache = _bench_decode(payloads, args.rounds, use_cache=False)
    t_cache = _bench_decode(payloads, args.rounds, use_cache=True)

    per_item_nocache = t_nocache / (args.total * args.rounds)
    per_item_cache = t_cache / (args.total * args.rounds)

    print("PCAPPER decode cache benchmark")
    print(f"Payloads: total={args.total} unique={args.unique} size={args.size} bytes rounds={args.rounds}")
    print(f"No cache: {t_nocache:.3f}s ({per_item_nocache*1e6:.2f} µs/item)")
    print(f"With cache: {t_cache:.3f}s ({per_item_cache*1e6:.2f} µs/item)")
    if t_cache > 0:
        print(f"Speedup: {t_nocache / t_cache:.2f}x")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

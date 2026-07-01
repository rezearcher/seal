#!/usr/bin/env python3
"""Seal Key Rotation Daemon — one-shot (cron) or persistent mode.

Usage:
    python3 seal-rotator.py --once               # single check (cron friendly)
    python3 seal-rotator.py --interval 3600      # persistent daemon

Installed at ~/.seal/bin/seal-rotator.py
"""

import argparse
import sys

from seal.key_manager import KeyManager


def main():
    parser = argparse.ArgumentParser(description="Seal key rotation daemon")
    parser.add_argument("--once", action="store_true",
                        help="check once and exit (cron mode)")
    parser.add_argument("--days-before", type=int, default=30,
                        help="rotate N days before expiry (default: 30)")
    parser.add_argument("--interval", type=int, default=3600,
                        help="seconds between checks (default: 3600)")
    parser.add_argument("--db", help="path to key database (default: ~/.seal/keys.db)")
    args = parser.parse_args()

    try:
        KeyManager.run_rotation_daemon(
            db_path=args.db,
            days_before=args.days_before,
            interval_seconds=args.interval,
            once=args.once,
        )
    except KeyboardInterrupt:
        print("\n[seal-rotator] stopped by signal", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

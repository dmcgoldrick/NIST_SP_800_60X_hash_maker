#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-0-Clause
# Author: Anonymous

import json
import argparse
from NIST_SP_800_63X_hash_maker.hashing import (
    normalize_secret,
    hash_all,
    benchmark_argon2id,
    verify_argon2id,
    verify_pbkdf2,
    hash_xxh128,
)

def main():
    parser = argparse.ArgumentParser(description="NIST SP 800 Hash Maker CLI Tool")
    parser.add_argument("--secret", type=str, default="P@ssw0rd🔒", help="Secret/password")
    parser.add_argument("--ram", type=int, default=512, help="RAM per worker (MB)")
    parser.add_argument("--threads", type=int, default=1, help="Threads per worker")
    parser.add_argument("--max-time", type=float, default=0.5, help="Max hash time")
    parser.add_argument("--verify", type=str, help="JSON record to verify")
    parser.add_argument("--rehash", action="store_true", help="Rehash Argon2id if params changed")
    args = parser.parse_args()

    if args.verify:
        with open(args.verify, "r") as f:
            record = json.load(f)
        valid, new_record = verify_secret_record(args.secret, record, rehash=args.rehash)
        print(f"Verification result: {valid}")
        if new_record:
            print("New Argon2id hash recommended due to updated parameters:")
            print(json.dumps(new_record, indent=2))
    else:
        print("Benchmarking Argon2id...")
        params, t = benchmark_argon2id(secret=args.secret.encode(), max_time=args.max_time,
                                       ram_mb=args.ram, threads=args.threads)
        print(f"Recommended parameters: {params}")
        print(f"Estimated hash time: {t:.3f} sec\n")
        print("Generating combined JSON hash record...")
        record = hash_all(args.secret, params)
        print(json.dumps(record, indent=2))

# allow running as module
if __name__ == "__main__":
    # lazy import of verify wrapper to avoid circular imports if needed
    from NIST_SP_800_63X_hash_maker.cli_helpers import verify_secret_record  # see note below
    main()


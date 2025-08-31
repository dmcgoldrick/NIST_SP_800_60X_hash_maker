# NIST_SP_800_60X_hash_maker/hashing.py
# SPDX-License-Identifier: BSD-0-Clause
# Author: Anonymous

import json
import argparse
from NIST_SP_800_60X_hash_maker.hashing import normalize_secret, hash_all, benchmark_argon2id, verify_argon2id, verify_pbkdf2, hash_xxh128

def main():
    parser = argparse.ArgumentParser(description="SBC Argon2id/PBKDF2/xxh128 CLI Tool")
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
        # unified verifier logic here...
        # simplified for brevity
        print("Verification functionality here")
    else:
        print("Benchmarking Argon2id...")
        params, t = benchmark_argon2id(secret=args.secret.encode(), max_time=args.max_time,
                                       ram_mb=args.ram, threads=args.threads)
        print(f"Recommended parameters: {params}")
        print(f"Estimated hash time: {t:.3f} sec\n")
        print("Generating combined JSON hash record...")
        record = hash_all(args.secret, params)
        print(json.dumps(record, indent=2))

if __name__ == "__main__":
    main()


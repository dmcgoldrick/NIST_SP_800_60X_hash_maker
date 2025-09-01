# NIST_SP_800_60X_hash_maker/hashing.py
# SPDX-License-Identifier: BSD-0-Clause
# Author: Anonymous

# hashing.py
# SPDX-License-Identifier: BSD-0-Clause
# Author: Anonymous

import os, base64,unicodedata, time
import xxhash
from hashlib import pbkdf2_hmac
from argon2.low_level import hash_secret, verify_secret, Type

# -----------------------------
# Global defaults (exported)
# -----------------------------
SALT_LEN = 16

# Default Argon2id params (safely overridden by benchmarking)
ARGON2_PARAMS = {
    "time_cost": 2,
    "memory_cost": 32768,  # 32 MB default
    "parallelism": 1,
    "hash_len": 32,
}

DEFAULT_HASH_LEN = 32
PBKDF2_ITERS = 310_000

def normalize_secret(secret: str | bytes) -> bytes:
    if isinstance(secret, bytes):
        secret = secret.decode("utf-8", errors="strict")
    return unicodedata.normalize("NFKC", secret).encode("utf-8")

def hash_argon2id(secret: str | bytes, params: dict) -> dict:
    salt = os.urandom(SALT_LEN)
    raw = normalize_secret(secret)
    digest = hash_secret(raw, salt, type=Type.ID, **params)
    return {
        "alg": "argon2id",
        "params": params,
        "salt_b64": base64.b64encode(salt).decode(),
        "hash_b64": base64.b64encode(digest).decode(),
    }

def verify_argon2id(secret: str | bytes, stored: dict) -> bool:
    raw = normalize_secret(secret)
    salt = base64.b64decode(stored["salt_b64"])
    digest = base64.b64decode(stored["hash_b64"])
    try:
        return verify_secret(digest, raw, salt, type=Type.ID, **stored["params"])
    except Exception:
        return False

def hash_pbkdf2(secret: str | bytes) -> dict:
    salt = os.urandom(SALT_LEN)
    raw = normalize_secret(secret)
    digest = pbkdf2_hmac("sha256", raw, salt, PBKDF2_ITERS, dklen=32)
    return {
        "alg": "pbkdf2-hmac-sha256",
        "iterations": PBKDF2_ITERS,
        "salt_b64": base64.b64encode(salt).decode(),
        "hash_b64": base64.b64encode(digest).decode(),
    }

def verify_pbkdf2(secret: str | bytes, stored: dict) -> bool:
    raw = normalize_secret(secret)
    salt = base64.b64decode(stored["salt_b64"])
    digest = base64.b64decode(stored["hash_b64"])
    new_digest = pbkdf2_hmac("sha256", raw, salt, stored["iterations"], dklen=len(digest))
    return digest == new_digest

def hash_xxh128(secret: str | bytes) -> str:
    raw = normalize_secret(secret)
    return xxhash.xxh128(raw).hexdigest()

def benchmark_argon2id(secret=b"testpassword", max_time=0.5, ram_mb=512, threads=1):
    time_cost = 2
    memory_cost = ram_mb * 1024 // 2
    parallelism = threads
    hash_len = DEFAULT_HASH_LEN

    salt = os.urandom(SALT_LEN)
    raw = secret

    while memory_cost > 16 * 1024:
        start = time.time()
        hash_secret(raw, salt, time_cost=time_cost, memory_cost=memory_cost,
                    parallelism=parallelism, hash_len=hash_len, type=Type.ID)
        elapsed = time.time() - start
        if elapsed <= max_time:
            break
        memory_cost = memory_cost // 2

    return {
        "time_cost": time_cost,
        "memory_cost": memory_cost,
        "parallelism": parallelism,
        "hash_len": hash_len
    }, elapsed

def hash_all(secret: str | bytes, argon2_params: dict) -> dict:
    return {
        "argon2id": hash_argon2id(secret, argon2_params),
        "pbkdf2": hash_pbkdf2(secret),
        "xxh128": hash_xxh128(secret)
    }


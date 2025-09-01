# NIST_SP_800_63X_hash_maker/cli_helpers.py

import base64
import json
from hashlib import pbkdf2_hmac
from argon2.low_level import Type, hash_secret_raw
from .hashing import normalize_secret, ARGON2_PARAMS, PBKDF2_ITERS

def verify_secret_record(secret: str, record: dict) -> bool:
    """Verify a secret against a combined JSON hash record."""

    raw = normalize_secret(secret)

    # Verify Argon2id
    if "argon2id" in record:
        r = record["argon2id"]
        salt = base64.b64decode(r["salt_b64"])
        expected = base64.b64decode(r["hash_b64"])
        digest = hash_secret_raw(
            raw,
            salt,
            time_cost=r["params"]["time_cost"],
            memory_cost=r["params"]["memory_cost"],
            parallelism=r["params"]["parallelism"],
            hash_len=r["params"]["hash_len"],
            type=Type.ID,
        )
        if digest != expected:
            return False

    # Verify PBKDF2
    if "pbkdf2" in record:
        r = record["pbkdf2"]
        salt = base64.b64decode(r["salt_b64"])
        expected = base64.b64decode(r["hash_b64"])
        digest = pbkdf2_hmac("sha256", raw, salt, r["iterations"], dklen=32)
        if digest != expected:
            return False

    return True


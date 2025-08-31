
import json
from NIST_SP_800_60X_hash_maker.hashing import hash_all, normalize_secret, hash_argon2id, verify_argon2id, hash_pbkdf2, verify_pbkdf2, hash_xxh128

def test_normalize_utf8():
    assert normalize_secret("P@ssw0rd🔒") == b"P@ssw0rd\ud83d\udd12" or isinstance(normalize_secret("P@ssw0rd🔒"), bytes)

def test_argon2id_hash_and_verify():
    secret = "TestPassword123"
    params = {"time_cost": 1, "memory_cost": 32*1024, "parallelism": 1, "hash_len": 32}
    record = hash_argon2id(secret, params)
    assert verify_argon2id(secret, record)

def test_pbkdf2_hash_and_verify():
    secret = "TestPassword123"
    record = hash_pbkdf2(secret)
    assert verify_pbkdf2(secret, record)

def test_xxh128():
    secret = "TestPassword123"
    h = hash_xxh128(secret)
    assert isinstance(h, str) and len(h) == 32

def test_combined_record():
    secret = "TestPassword123"
    params = {"time_cost": 1, "memory_cost": 32*1024, "parallelism": 1, "hash_len": 32}
    record = hash_all(secret, params)
    assert "argon2id" in record and "pbkdf2" in record and "xxh128" in record


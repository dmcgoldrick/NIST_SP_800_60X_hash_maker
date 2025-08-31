# NIST_SP_800_60X_hash_maker

**SBC-friendly Argon2id/PBKDF2/xxh128 hash benchmarking and CLI tool**  
Compliant with **NIST SP 800-63 recommendations**.

It provides:

- **Argon2id** hashing with hardware-aware parameter recommendation  
- **PBKDF2-HMAC-SHA256** hashing  
- **xxh128** hashing for fast deduplication  
- **UTF-8 NFKC normalization**  
- **JSON output** for storage and verification  
- Optional **verification and rehashing** if Argon2id parameters change

---

## Installation

```bash
git clone https://github.com/dmcgoldrick/NIST_SP_800_60X_hash_maker.git
cd NIST_SP_800_60X_hash_maker
pip install .

## License

This project is released under the **BSD 0-Clause License** (Zero-Clause BSD).  
No attribution is required. Use, copy, modify, and distribute freely.

[LICENSE] for full text.


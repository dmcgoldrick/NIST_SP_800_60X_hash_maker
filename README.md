# NIST_SP_800_63X_hash_maker

## BackGround
The Entailment Network is a secure, distributed framework for computational collaboration and knowledge sharing.
It establishes identity, transport, and trust mechanisms that enable machines, users, and reward systems to interact 
reliably while preserving privacy and protecting resources.

## Key Features

# Secure Identity Management

- Strong authentication for machines, users, and reward participants.

# Transport & Key Management

- Encrypted communication channels.

- Robust key distribution and lifecycle handling.

# Brokering of Secure Computational Units

- Encapsulation of in-network computation.

- Verifiable execution without external interference.

- P2P Anonymity

# Privacy-preserving peer-to-peer interactions (traversal).

- Machine Metadata & Normalized Encodings

- Standardized descriptors for interoperability.

- Consistent representation across heterogeneous systems.

# "Entailtrons" as Carriers

Like electrons in a circuit, Entailtrons traverse the network.
Earn rewards for contributions. Protect access, distributed resources, 
and produce computational and query results.

# This is a command line tool that shows basic security for an Entailtron 
It is here to showcase our NIST-informed implementation for users on an 
entailed network for a much larger project.

**SBC-friendly Argon2id/PBKDF2/xxh128 hash benchmarking and CLI tool**  
Compliant with **NIST SP 800-63 recommendations**.
https://pages.nist.gov/800-63-3/sp800-63-3.html

It provides:

- **Argon2id** hashing with hardware-aware parameter recommendation  
- **PBKDF2-HMAC-SHA256** hashing  
- **xxh128** hashing for fast deduplication  
- **UTF-8 NFKC normalization**  
- **JSON output** for storage and verification with JWT  
- Optional **verification and rehashing** if Argon2id parameters change

---

## Installation

```bash
git clone https://github.com/dmcgoldrick/NIST_SP_800_63X_hash_maker.git
cd NIST_SP_800_63X_hash_maker
pip install .

## License

This project is released under the **BSD 0-Clause License** (Zero-Clause BSD).  
No attribution is required. Use, copy, modify, and distribute freely.

[LICENSE] for full text.


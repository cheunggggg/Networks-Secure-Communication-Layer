# Secure Communication Layer

A TLS-like secure channel implemented in C over TCP. Features a custom handshake protocol with mutual authentication, certificate validation, and authenticated encryption for all data in transit.
Created by Brandon Cheung, Maxime Morize, and Selena Yu for COM SCI 118 at UCLA. FALL 2025

---

## Protocol Overview

The handshake establishes a shared secret via ECDH and derives symmetric keys before any data is exchanged. All messages are encoded in a custom TLV (Type-Length-Value) format.

```
Client                                    Server
  |                                          |
  |──── Client Hello (nonce, pub key) ──────>|
  |                                          |
  |<─── Server Hello (nonce, cert,  ─────────|
  |          pub key, handshake sig)         |
  |                                          |
  |──── Finished (transcript HMAC) ─────────>|
  |                                          |
  |<════ Encrypted Data (AES-256-CBC) ═══════|
  |═════ Encrypted Data (AES-256-CBC) ══════>|
```

### Handshake Steps

**1. Client Hello** — Client generates an ephemeral EC key pair, produces a 32-byte random nonce, and sends both. The full serialized message is saved to a transcript buffer.

**2. Server Hello** — Server generates its own ephemeral EC key pair and nonce, then attaches its certificate (DNS name, public key, lifetime, CA signature). It signs the concatenation of `[Client Hello | server nonce | cert | server pub key]` using its certificate private key, then switches back to the ephemeral key to derive the ECDH shared secret. Encryption and MAC keys are derived via HKDF-SHA256 over the transcript.

**3. Client Finished** — Client verifies the server certificate against the CA public key, checks the DNS name and certificate lifetime, then verifies the handshake signature. It derives the same shared secret and keys, then sends a `Finished` message containing an HMAC-SHA256 over the full transcript (Client Hello + Server Hello).

**4. Server verifies Finished** — Server recomputes the transcript HMAC and compares it to the client's value. A mismatch causes immediate termination. Both sides enter `DATA_STATE`.

### Data State

Each message is wrapped in a `DATA` TLV:

```
DATA
├── IV          (16 bytes, random per message)
├── CIPHERTEXT  (AES-256-CBC encrypted plaintext)
└── MAC         (HMAC-SHA256 over serialized IV + CIPHERTEXT TLVs)
```

The MAC is verified before decryption. A MAC failure causes immediate termination (`exit(5)`).

---

## Cryptography

| Primitive | Algorithm | Details |
|-----------|-----------|---------|
| Key exchange | ECDH | P-256 (prime256v1) ephemeral keys |
| Server auth | ECDSA | SHA-256, signed by CA private key |
| Key derivation | HKDF-SHA256 | Transcript as salt; `"enc"` / `"mac"` as info strings |
| Encryption | AES-256-CBC | Random 16-byte IV per message |
| Integrity | HMAC-SHA256 | Over serialized IV + ciphertext TLVs |
| Nonces | CSPRNG | 32 bytes via `RAND_bytes` |

All cryptographic operations use **OpenSSL's EVP API**.

---

## TLV Message Format

```
[1 byte: type] [1 or 3 bytes: length] [N bytes: value]
```

Lengths ≤ 252 use a single byte. Lengths > 252 use `0xFD` followed by a 2-byte big-endian length. Up to 10 children per TLV node.

| Type | Value | Description |
|------|-------|-------------|
| `NONCE` | `0x01` | 32-byte random nonce |
| `PUBLIC_KEY` | `0x02` | DER-encoded EC public key |
| `TRANSCRIPT` | `0x04` | HMAC-SHA256 over handshake transcript |
| `CLIENT_HELLO` | `0x10` | Nonce + public key |
| `SERVER_HELLO` | `0x20` | Nonce + certificate + public key + handshake signature |
| `HANDSHAKE_SIGNATURE` | `0x21` | ECDSA signature over handshake data |
| `FINISHED` | `0x30` | Transcript HMAC |
| `CERTIFICATE` | `0xA0` | DNS name + public key + lifetime + CA signature |
| `DNS_NAME` | `0xA1` | Null-terminated hostname string |
| `SIGNATURE` | `0xA2` | ECDSA signature |
| `LIFETIME` | `0xA3` | Two 8-byte big-endian Unix timestamps (not_before, not_after) |
| `DATA` | `0x50` | IV + ciphertext + MAC |
| `IV` | `0x51` | 16-byte AES initialization vector |
| `CIPHERTEXT` | `0x52` | AES-256-CBC encrypted payload |
| `MAC` | `0x53` | HMAC-SHA256 digest |

---

## File Structure

```
.
├── client.c        — TCP client: connects, drives security handshake, relays stdio
├── server.c        — TCP server: listens, accepts one client, drives security handshake
├── security.c      — Handshake state machine (CLIENT_*/SERVER_* states → DATA_STATE)
├── security.h      — Public interface: init_sec(), input_sec(), output_sec()
├── libsecurity.c   — OpenSSL wrappers: keygen, ECDH, HKDF, AES-CBC, HMAC, sign/verify
├── libsecurity.h   — Declarations for all cryptographic primitives
├── io.c            — Non-blocking stdin/stdout helpers
├── io.h
├── consts.h        — State constants, TLV type codes, inline TLV serialization
├── gen_cert.c      — Certificate generation utility (signs server key with CA key)
└── Makefile
```

---

## Building

Requires **OpenSSL** (libcrypto). The Makefile defaults to `/opt/homebrew/opt/openssl` (Homebrew on macOS). Adjust `OPENSSL_PREFIX` for your system.

```bash
# macOS (Homebrew)
make

# Linux (system OpenSSL)
make OPENSSL_PREFIX=/usr

# Clean all build artifacts
make clean
```

This produces three binaries: `server`, `client`, and `gen_cert`.

---

## Certificate Generation

Certificates are created by signing a server's public key with a CA private key:

```bash
./gen_cert <server_private_key> <ca_private_key> <dns_name> <output_file> [not_before] [not_after]
```

- `not_before` / `not_after` are Unix timestamps. If omitted, the certificate is valid for **1 year** from the current time.
- The output file (e.g. `server_cert.bin`) is a serialized TLV containing the DNS name, server public key, lifetime, and CA signature.

---

## Usage

```bash
# Terminal 1 — start server on port 8080
./server 8080

# Terminal 2 — connect client to server
./client localhost 8080

# Pass a third argument to either binary to deliberately send bad MACs (for testing)
./client localhost 8080 bad
```

The client and server relay stdin → encrypted channel → stdout. Typed input on one end appears as decrypted output on the other.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `1` | General error (bad args, socket failure, malformed message) |
| `2` | DNS name mismatch in certificate |
| `3` | Handshake signature verification failed |
| `4` | Transcript HMAC mismatch (Finished message) |
| `5` | Data MAC verification failed |
| `6` | Unexpected message type received |
| `255` | Missing or invalid key / certificate file |

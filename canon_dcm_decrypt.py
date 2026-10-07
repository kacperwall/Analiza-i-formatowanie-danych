#!/usr/bin/env python3
"""
Canon iR-ADV device config backup (.dcm -> .enc) decryptor.
AES-GCM, key derived from export password + salt (from MANIFEST.MF).

Usage:
    python3 canon_dcm_decrypt.py <enc_file> <MANIFEST.MF> [password]

If password omitted, it is read interactively (not echoed).
Tries several key-derivation candidates and verifies each via the GCM tag.
The correct derivation authenticates; everything else fails cleanly.
"""
import sys, os, hashlib, getpass, base64

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    sys.exit("pip install cryptography  (or: pip install cryptography --break-system-packages)")


def parse_manifest(path):
    d = {}
    with open(path, "r", errors="replace") as f:
        for line in f:
            if ":" in line:
                k, _, v = line.partition(":")
                d[k.strip().lower()] = v.strip()
    return d


def try_decrypt(key, iv, ct_and_tag, aad):
    """ct_and_tag = ciphertext with 16-byte GCM tag appended."""
    try:
        return AESGCM(key).decrypt(iv, ct_and_tag, aad)
    except Exception:
        return None


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    enc_path, man_path = sys.argv[1], sys.argv[2]
    pw = sys.argv[3] if len(sys.argv) > 3 else getpass.getpass("Export password: ")
    pwb = pw.encode()

    man = parse_manifest(man_path)
    salt = bytes.fromhex(man["salt"])
    iv = bytes.fromhex(man["iv"])
    tag = bytes.fromhex(man["tag"])
    print(f"[*] salt={salt.hex()} iv={iv.hex()} ({len(iv)}B) tag={tag.hex()} ({len(tag)}B)")

    ct = open(enc_path, "rb").read()
    ct_tag = ct + tag  # cryptography expects tag appended to ciphertext

    # candidate keys (both AES-128 = 16B and AES-256 = 32B where relevant)
    cands = []

    def add(name, kb):
        if len(kb) in (16, 24, 32):
            cands.append((name, kb))
        # also allow truncations commonly used
        if len(kb) >= 32:
            cands.append((name + "[:32]", kb[:32]))
        if len(kb) >= 16:
            cands.append((name + "[:16]", kb[:16]))

    add("sha256(pw)", hashlib.sha256(pwb).digest())
    add("sha256(pw+salt)", hashlib.sha256(pwb + salt).digest())
    add("sha256(salt+pw)", hashlib.sha256(salt + pwb).digest())
    add("md5(pw)", hashlib.md5(pwb).digest())
    add("sha1(pw+salt)", hashlib.sha1(pwb + salt).digest())
    add("sha1(salt+pw)", hashlib.sha1(salt + pwb).digest())

    for iters in (1, 100, 1000, 1024, 2000, 4096, 10000, 100000):
        for h in ("sha256", "sha1"):
            for dklen in (16, 32):
                k = hashlib.pbkdf2_hmac(h, pwb, salt, iters, dklen)
                cands.append((f"pbkdf2-{h}-{iters}-{dklen}B", k))

    # AAD candidates: none, or the salt, or the digest
    aads = [None, b"", salt]
    if "digest" in man:
        try:
            aads.append(base64.b64decode(man["digest"]))
        except Exception:
            pass

    for name, key in cands:
        for aad in aads:
            pt = try_decrypt(key, iv, ct_tag, aad)
            if pt is not None:
                out = enc_path + ".dec"
                open(out, "wb").write(pt)
                print(f"[+] SUCCESS  key={name}  aad={'none' if aad is None else aad.hex()[:16]}")
                print(f"[+] decrypted {len(pt)} bytes -> {out}")
                # quick peek
                head = pt[:200]
                printable = bytes(c if 32 <= c < 127 or c in (9,10,13) else 46 for c in head)
                print("[*] head:", printable.decode("ascii", "replace"))
                return
    print("[-] No candidate worked. Canon KDF differs; pivot to SMB coercion.")


if __name__ == "__main__":
    main()

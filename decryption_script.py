from hashlib import sha256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BITS = 18

msg = b"Rudy and Seria test their locks before sealing the secret scroll."

sample = {
    "iv1": "d1b5eaee9f0415feaa5a8e5ebbc73707",
    "iv2": "4e0b0e2c611627f65b734feb60c92e8d",
    "ct": "46a37254939501a029561621e30eab4fdc00b61722edc6e9403850c0880cc4165e737e301bd0a14035831218d3afc7f7cbb7748d9f7e16caf3a9d14a93ffe3992fc9cbce69870d94e3ad7ca11558d78c",
}

target = {
    "iv1": "53916a0f6433ee40c86494b086ca3dfb",
    "iv2": "74d1add472e0770e65c952c86db705e6",
    "ct": "aabc0404de5ddc44d1bb63cb6d7ad634437d19ed05639d79232149c6b5f07fcfba685f1ebf02350fe9cfde85a4655c219e7c08eff9570ff1d26534697a6dc3dcc5c0c75f0fc47f8a6d1fc41ec5eaa9318da4f8a0376cdc065d484b6a30717c77b9dd3b05b42d517ec4cea2a25f2fa70b",
}


def key(x: int) -> bytes:
    return sha256(x.to_bytes(3, "big")).digest()[:16]


def pad(m: bytes) -> bytes:
    n = 16 - len(m) % 16
    return m + bytes([n]) * n


def unpad(m: bytes) -> bytes:
    n = m[-1]
    if 1 <= n <= 16 and m[-n:] == bytes([n]) * n:
        return m[:-n]
    raise ValueError("bad padding")


def cbc_enc(k: bytes, iv: bytes, data: bytes) -> bytes:
    enc = Cipher(algorithms.AES(k), modes.CBC(iv)).encryptor()
    return enc.update(data) + enc.finalize()


def cbc_dec(k: bytes, iv: bytes, data: bytes) -> bytes:
    dec = Cipher(algorithms.AES(k), modes.CBC(iv)).decryptor()
    return dec.update(data) + dec.finalize()


def main():
    iv1_s = bytes.fromhex(sample["iv1"])
    iv2_s = bytes.fromhex(sample["iv2"])
    ct_s = bytes.fromhex(sample["ct"])

    padded_msg = pad(msg)

    # Meet-in-the-middle:
    # sample_ct = AES_CBC(key(b), iv2, AES_CBC(key(a), iv1, padded_msg))
    #
    # For every a, compute middle = AES_CBC(key(a), iv1, padded_msg).
    # For every b, decrypt sample_ct to get the same middle.
    table = {}

    print("[+] Building table for a...")
    for a in range(1 << BITS):
        middle = cbc_enc(key(a), iv1_s, padded_msg)
        table[middle] = a

    print("[+] Searching for b...")
    found = None
    for b in range(1 << BITS):
        middle = cbc_dec(key(b), iv2_s, ct_s)
        if middle in table:
            a = table[middle]
            if a != b:
                found = (a, b)
                print(f"[+] Found a = {a}, b = {b}")
                break

    if found is None:
        raise SystemExit("[-] No keys found")

    a, b = found

    # Verify on sample
    middle_sample = cbc_enc(key(a), iv1_s, padded_msg)
    assert cbc_enc(key(b), iv2_s, middle_sample) == ct_s

    # Decrypt target
    iv1_t = bytes.fromhex(target["iv1"])
    iv2_t = bytes.fromhex(target["iv2"])
    ct_t = bytes.fromhex(target["ct"])

    middle_target = cbc_dec(key(b), iv2_t, ct_t)
    padded_flag = cbc_dec(key(a), iv1_t, middle_target)
    flag = unpad(padded_flag)

    print(f"[+] a = {a}")
    print(f"[+] b = {b}")
    print(f"[+] flag = {flag!r}")
    print(flag.decode(errors="replace"))


if __name__ == "__main__":
    main()
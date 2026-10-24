from hashlib import sha256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BITS = 18

def key(x):
    return sha256(x.to_bytes(3, "big")).digest()[:16]

def decrypt_block(ciphertext, key_bytes, iv):
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def encrypt_block(plaintext, key_bytes, iv):
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

# Given sample data
msg = b'Rudy and Seria test their locks before sealing the secret scroll.'
n = 16 - len(msg) % 16
padded_msg = msg + bytes([n]) * n

iv1 = bytes.fromhex('6e80055e203445a814e0362ec61a6825')
iv2 = bytes.fromhex('0927eec0b78448c44189f16e960d1aaa')
ct = bytes.fromhex('3604d383d6be7824453a95abd0500b9315cf4296036fb34826608ada016225b17e2dcdade1fb551b41f007adfd3997a3f35ae963acae50425f399df723b2f97f4f0775cd275e9c1ea695f6b16d20ffe9')

print("[*] Building table for a (Meet-in-the-Middle)...")
table = {}
for a in range(1 << BITS):
    k = key(a)
    c_a = encrypt_block(padded_msg, k, iv1)
    table[c_a] = a

print("[*] Searching for b...")
found_a, found_b = None, None
for b in range(1 << BITS):
    k = key(b)
    p_b = decrypt_block(ct, k, iv2)
    if p_b in table:
        found_a = table[p_b]
        found_b = b
        break

print(f"[+] Found incantations: a = {found_a}, b = {found_b}")

# Target decryption
target_iv1 = bytes.fromhex('c6906ea22e71326078ceecc8f717b300')
target_iv2 = bytes.fromhex('fc8a20092cdcddccc5fa8ebf72f5ba13')
target_ct = bytes.fromhex('7ab7b02e5434779ce26c41cb0ce9a81f352ba5bb196732706ee466d91f5f04560c62473acf74e60846c7dbb73ef37ec256fa34698fdb641e6d33c751f0e428e4e0431bbb0085615ff3ff07ddb622850a69530c19890c196d797445436a7d16eea05c5771d49f71da83ba88398e297c74')

step1 = decrypt_block(target_ct, key(found_b), target_iv2)
step2 = decrypt_block(step1, key(found_a), target_iv1)

pad_len = step2[-1]
flag = step2[:-pad_len]
print(f"[+] Flag: {flag.decode()}")
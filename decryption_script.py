import sys
from Cryptodome.Cipher import AES
import binascii

# Challenge Parameters
bits = 18
msg = b'Rudy and Seria test their locks before sealing the secret scroll.'

# Sample data
sample_iv1 = bytes.fromhex('265933ad7c6fd6c5a657b5c70ae2929e')
sample_iv2 = bytes.fromhex('732afbb7f0fd8160a6a737ccd61c83e1')
sample_ct  = bytes.fromhex('87049038343886a2a1740aba3029ef817e2412d057d177e946f92f476e2d10ba0ddbd3920df9985a5bffdc3a98c1b67cd37f9ed6c6d7563390c710b3d465a1e5143dc64d39f6c57207dd44786752ff73')

target_iv1 = bytes.fromhex('763d9b341e103d2f7497a78d0653c62e')
target_iv2 = bytes.fromhex('08c825e69434781ff9757147fc1a4370')
target_ct  = bytes.fromhex('33ec0fe66ec363c12747c617d4935aff5b59bf955844bbfd8637de18e311ac0d157d869db0e351b20ec88aa8e7f955e57250182696a2e5b8bfc98b15aa0435a3ac10578c298b7a762581dacd6697b133b68ecd1f828a1546cf1c8f3046c296665ffb6d9ff42d1cead32b5618afa8360e')

def pad_key(k_int):
    # Padding 18-bit integer into 16-byte key (AES-128 format)
    return k_int.to_bytes(16, byteorder='big')

# Step 1: Precompute forward encryption table for Layer 1
table = {}
print("[+] Building Meet-in-the-Middle table for Key 1...")
for k1 in range(1 << bits):
    key1 = pad_key(k1)
    cipher1 = AES.new(key1, AES.MODE_CBC, sample_iv1)
    
    # We only need to store the first block to match speed
    mid_block = cipher1.encrypt(msg[:16])
    table[mid_block] = k1

print(f"[+] Table built with {len(table)} entries.")

# Step 2: Search backward using Layer 2 decryption
print("[+] Searching for matching Key 2...")
found_k1 = None
found_k2 = None

for k2 in range(1 << bits):
    key2 = pad_key(k2)
    cipher2 = AES.new(key2, AES.MODE_CBC, sample_iv2)
    
    # Decrypt first ciphertext block backwards
    mid_decrypted = cipher2.decrypt(sample_ct[:16])
    
    if mid_decrypted in table:
        found_k1 = table[mid_decrypted]
        found_k2 = k2
        print(f"[!] Match found! k1 = {found_k1}, k2 = {found_k2}")
        break

# Step 3: Decrypt target ciphertext using recovered keys
key1 = pad_key(found_k1)
key2 = pad_key(found_k2)

# Layer 2 Decryption
cipher2 = AES.new(key2, AES.MODE_CBC, target_iv2)
mid_ct = cipher2.decrypt(target_ct)

# Layer 1 Decryption
cipher1 = AES.new(key1, AES.MODE_CBC, target_iv1)
secret_msg = cipher1.decrypt(mid_ct)

print("\n[+] Secret Scroll Content:")
print(secret_msg.decode('utf-8', errors='ignore'))
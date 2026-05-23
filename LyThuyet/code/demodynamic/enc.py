from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pathlib import Path
import hashlib
import os

KEY = b"0123456789abcdef0123456789abcdef"  

input_path = Path("testass-plugin.jar")
output_path = Path("test.enc")

plain = input_path.read_bytes()

sha256 = hashlib.sha256(plain).hexdigest()
print("[+] Plain JAR SHA-256:", sha256)

iv = os.urandom(12)
aesgcm = AESGCM(KEY)
ciphertext = aesgcm.encrypt(iv, plain, None)

output_path.parent.mkdir(parents=True, exist_ok=True)
output_path.write_bytes(iv + KEY + ciphertext)

print("[+] Encrypted saved to:", output_path)

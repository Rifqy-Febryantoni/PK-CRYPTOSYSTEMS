# crypter.py
import random
import math
from binascii import unhexlify, hexlify

# --- DES IMPLEMENTATION ---
IP = [58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7]
FP = [40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25]
E = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1]
P = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25]
PC1 = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4]
PC2 = [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32]
ROTATIONS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]
S_BOXES = [
[[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],[0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],[4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],[15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
[[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],[3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],[0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],[13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
[[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],[13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],[13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],[1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
[[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],[13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],[10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],[3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
[[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],[14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],[4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],[11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
[[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],[10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],[9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],[4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
[[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],[13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],[1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],[6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
[[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],[1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],[7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],[2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]
]

def bytes_to_bits(b):
    bits = []
    for byte in b:
        for i in range(8)[::-1]: bits.append((byte >> i) & 1)
    return bits

def bits_to_bytes(bits):
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i+8]: byte = (byte << 1) | bit
        out.append(byte)
    return bytes(out)

def permute(bits, table): return [bits[i-1] for i in table]
def left_rotate(l, n): return l[n:] + l[:n]

def generate_subkeys(key64bytes):
    kb = bytes_to_bits(key64bytes)
    permuted = permute(kb, PC1)
    C, D = permuted[:28], permuted[28:]
    subkeys = []
    for r in range(16):
        C = left_rotate(C, ROTATIONS[r])
        D = left_rotate(D, ROTATIONS[r])
        subkeys.append(permute(C + D, PC2))
    return subkeys

def sbox_substitution(bits48):
    out32 = []
    for i in range(8):
        chunk = bits48[i*6:(i+1)*6]
        row = (chunk[0] << 1) | chunk[5]
        col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
        val = S_BOXES[i][row][col]
        for j in range(4)[::-1]: out32.append((val >> j) & 1)
    return out32

def feistel(R, subkey):
    expanded = permute(R, E)
    xored = [a ^ b for a, b in zip(expanded, subkey)]
    s_out = sbox_substitution(xored)
    return permute(s_out, P)

def des_block_encrypt(block8bytes, subkeys):
    bits = bytes_to_bits(block8bytes)
    ip = permute(bits, IP)
    L, R = ip[:32], ip[32:]
    for i in range(16):
        f_out = feistel(R, subkeys[i])
        newL, newR = R, [l ^ f for l, f in zip(L, f_out)]
        L, R = newL, newR
    cipher_bits = permute(R + L, FP)
    return bits_to_bytes(cipher_bits)

def des_block_decrypt(block8bytes, subkeys):
    return des_block_encrypt(block8bytes, list(reversed(subkeys)))

def pad8(data):
    while len(data) % 8 != 0: data += b'\x00'
    return data

def des_encrypt_text(plaintext, key):
    data = pad8(plaintext.encode('utf-8'))
    key_bytes = pad8(key.encode('utf-8'))[:8]
    subkeys = generate_subkeys(key_bytes)
    ciphertext = b''.join(des_block_encrypt(data[i:i+8], subkeys) for i in range(0, len(data), 8))
    return hexlify(ciphertext).upper().decode()

def des_decrypt_text(cipher_hex, key):
    cipher = unhexlify(cipher_hex)
    key_bytes = pad8(key.encode('utf-8'))[:8]
    subkeys = generate_subkeys(key_bytes)
    plain = b''.join(des_block_decrypt(cipher[i:i+8], subkeys) for i in range(0, len(cipher), 8))
    return plain.rstrip(b'\x00').decode('utf-8', errors='ignore')

# --- RSA & HASH IMPLEMENTATION ---

def egcd(a, b):
    if a == 0: return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def mod_inverse(a, m):
    g, x, y = egcd(a, m)
    if g != 1: raise Exception('Modular inverse does not exist')
    else: return x % m

def is_prime(n, k=5):
    if n < 2: return False
    if n == 2 or n == 3: return True
    if n % 2 == 0: return False
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1: continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else: return False
    return True

def generate_large_prime(bits=512):
    while True:
        p = random.getrandbits(bits)
        p |= (1 << bits - 1) | 1
        if is_prime(p): return p

def rsa_generate_keypair(bits=1024):
    print(f"Generating {bits}-bit RSA keypair... (this may take a moment)")
    p = generate_large_prime(bits // 2)
    q = generate_large_prime(bits - (bits // 2))
    while p == q: q = generate_large_prime(bits - (bits // 2))
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    if math.gcd(e, phi) != 1: e = 3
    d = mod_inverse(e, phi)
    print("Keypair generated.")
    return ((n, e), (n, d))

def rsa_encrypt_bytes(msg_bytes, public_key):
    n, e = public_key
    m_int = int.from_bytes(msg_bytes, 'big')
    if m_int >= n: raise Exception("Message too large for this key size")
    return pow(m_int, e, n)

def rsa_decrypt_bytes(c_int, private_key, num_bytes):
    n, d = private_key
    m_int = pow(c_int, d, n)
    return m_int.to_bytes(num_bytes, 'big')

# --- DIGITAL SIGNATURE UTILS ---

def manual_hash(data: str) -> int:
    hash_val = 14695981039346656037
    for char in data:
        hash_val = hash_val ^ ord(char)
        hash_val = (hash_val * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return hash_val

def rsa_sign(message: str, private_key: tuple) -> str:
    h_int = manual_hash(message)
    n, d = private_key
    signature_int = pow(h_int, d, n)
    # Signature 128 bytes hex encoded
    return hexlify(signature_int.to_bytes(128, 'big')).decode()

def rsa_verify(message: str, signature_hex: str, sender_public_key: tuple) -> bool:
    try:
        n, e = sender_public_key
        signature_int = int.from_bytes(unhexlify(signature_hex), 'big')
        decrypted_hash = pow(signature_int, e, n)
        current_message_hash = manual_hash(message)
        return decrypted_hash == current_message_hash
    except Exception:
        return False
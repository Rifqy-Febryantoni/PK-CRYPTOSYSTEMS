# socket_client_a.py

import os
import time
import socket
import threading
import sys
import crypter as crypter

# --- Konfigurasi ---
KDC_HOST = '192.168.1.10'
KDC_PORT = 9000
CHAT_HOST = '192.168.1.12'
CHAT_PORT = 9001

A_PUBLIC_KEY = 'a_public.key'
A_PRIVATE_KEY = 'a_private.key'

def save_key(filename, key_tuple):
    n, val = key_tuple
    with open(filename, 'w') as f: f.write(f"n = {n}\nkey_val = {val}\n")

def load_key(filename):
    if not os.path.exists(filename): return None
    key_data = {}
    with open(filename, 'r') as f: exec(f.read(), key_data)
    return (key_data['n'], key_data['key_val'])

def message_receiver(sock, des_key, sender_pub_key):
    print("\n[A] Penerima pesan aktif...")
    try:
        while True:
            data = sock.recv(4096).decode('utf-8')
            if not data: break
            
            if "||" in data:
                sig_hex, enc_msg = data.split("||")
                plaintext = crypter.des_decrypt_text(enc_msg, des_key)
                is_valid = crypter.rsa_verify(plaintext, sig_hex, sender_pub_key)
                status = "✅ VALID" if is_valid else "❌ PALSU/CORRUPT"
                print(f"\n[Incoming from B] [{status}]: {plaintext}")
                print("Enter message (or 'exit'): ", end="", flush=True)
            else:
                print(f"\n[Raw Data]: {data}")

    except Exception as e:
        print(f"[A] Error receiver: {e}")
        os._exit(1)

# --- UTAMA ---
print("--- Client A (Initiator) ---")

# 1. Cek / Buat Kunci
if not os.path.exists(A_PRIVATE_KEY):
    print("Membuat kunci RSA A...")
    pub, priv = crypter.rsa_generate_keypair(bits=1024)
    save_key(A_PUBLIC_KEY, pub)
    save_key(A_PRIVATE_KEY, priv)
    
    # Auto Register
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_kdc:
            s_kdc.connect((KDC_HOST, KDC_PORT))
            n, e = pub
            s_kdc.sendall(f"REGISTER:A:{n}:{e}".encode('utf-8'))
            if s_kdc.recv(1024) == b'OK:REGISTERED':
                print("[A] Sukses mendaftar. Jalankan ulang untuk chat.")
    except: pass
    exit()

a_private_key = load_key(A_PRIVATE_KEY)
IS_HACKER_MODE = "--hack" in sys.argv

# 2. Minta Kunci ke KDC
try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_kdc:
        s_kdc.connect((KDC_HOST, KDC_PORT))
        s_kdc.sendall(b"REQUEST:A:B")
        
        # Terima Kunci A
        len_a = int.from_bytes(s_kdc.recv(4), 'big')
        c_bytes_for_a = s_kdc.recv(len_a)
        
        # Terima Tiket B
        len_b = int.from_bytes(s_kdc.recv(4), 'big')
        c_bytes_for_b = s_kdc.recv(len_b)

except Exception as e:
    print(f"[A] Gagal ke KDC: {e}")
    exit()

# Dekripsi Session Key
c_int_for_a = int.from_bytes(c_bytes_for_a, 'big')
des_key_bytes = crypter.rsa_decrypt_bytes(c_int_for_a, a_private_key, 8)
des_key_str = des_key_bytes.decode('utf-8')
print(f"[A] Session Key: {des_key_str}")

# 3. Koneksi Chat ke B
try:
    s_chat = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_chat.connect((CHAT_HOST, CHAT_PORT))
    
    # A. Kirim Tiket
    s_chat.sendall(c_bytes_for_b)
    
    # B. Handshake Public Key
    print("[A] Handshake Public Key...")
    my_n, my_e = load_key(A_PUBLIC_KEY)
    enc_pubkey = crypter.des_encrypt_text(f"{my_n}:{my_e}", des_key_str)
    s_chat.sendall(enc_pubkey.encode('utf-8'))
    
    enc_b_pub = s_chat.recv(4096).decode('utf-8')
    b_pub_str = crypter.des_decrypt_text(enc_b_pub, des_key_str)
    b_n, b_e = map(int, b_pub_str.split(':'))
    b_public_key = (b_n, b_e)
    
    # 4. Mulai Receiver
    receiver = threading.Thread(target=message_receiver, args=(s_chat, des_key_str, b_public_key), daemon=True)
    receiver.start()
    
    if IS_HACKER_MODE:
        print("\n[⚠️ HACKER MODE AKTIF] Tanda tangan akan dipalsukan!")

    while True:
        plaintext = input("Enter message (or 'exit'): ")
        if plaintext.lower() == 'exit': break
        
        # --- LOGIKA HACKER ---
        signature = crypter.rsa_sign(plaintext, a_private_key) # Signature Asli
        
        if IS_HACKER_MODE:
            signature = "deadbeef00000000deadbeef00000000" # Signature Palsu (Hex valid)
            print(f"[HACKER] Sending FAKE signature: {signature}")
        
        ciphertext = crypter.des_encrypt_text(plaintext, des_key_str)
        payload = f"{signature}||{ciphertext}"
        
        print(f"[Log A] Payload: {payload[:20]}...")
        s_chat.sendall(payload.encode('utf-8'))

except Exception as e:
    print(f"[A] Error Chat: {e}")
finally:
    s_chat.close()
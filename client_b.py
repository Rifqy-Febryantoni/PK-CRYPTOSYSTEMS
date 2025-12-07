# socket_client_b.py

import os
import time
import socket
import threading
import crypter as crypter

# --- Konfigurasi Jaringan ---
KDC_HOST = '192.168.1.10'
KDC_PORT = 9000
LISTEN_HOST = '0.0.0.0'
CHAT_PORT = 9001

# --- File Kunci ---
B_PUBLIC_KEY = 'b_public.key'
B_PRIVATE_KEY = 'b_private.key'

def save_key(filename, key_tuple):
    n, val = key_tuple
    with open(filename, 'w') as f: f.write(f"n = {n}\nkey_val = {val}\n")

def load_key(filename):
    if not os.path.exists(filename): return None
    key_data = {}
    with open(filename, 'r') as f: exec(f.read(), key_data)
    return (key_data['n'], key_data['key_val'])

def message_receiver(sock, des_key, sender_pub_key):
    print("\n[B] Penerima pesan aktif...")
    try:
        while True:
            data = sock.recv(4096).decode('utf-8')
            if not data: break
            
            # Cek Format: SIGNATURE || CIPHERTEXT
            if "||" in data:
                sig_hex, enc_msg = data.split("||")
                
                # 1. Dekripsi Pesan (DES)
                plaintext = crypter.des_decrypt_text(enc_msg, des_key)
                
                # 2. Verifikasi Tanda Tangan (RSA Public Key A)
                is_valid = crypter.rsa_verify(plaintext, sig_hex, sender_pub_key)
                
                status = "✅ VALID" if is_valid else "❌ PALSU/CORRUPT"
                
                print(f"\n[Incoming from A] [{status}]: {plaintext}")
                print("Enter message (or 'exit'): ", end="", flush=True)
            else:
                # Fallback jika format salah
                print(f"\n[Raw Data]: {data}")

    except Exception as e:
        print(f"[B] Error di receiver: {e}")
        os._exit(1)

# --- UTAMA ---
print("--- Client B (Responder) ---")

# 1. Buat Kunci jika belum ada
if not os.path.exists(B_PRIVATE_KEY):
    print("Membuat kunci RSA untuk B...")
    pub, priv = crypter.rsa_generate_keypair(bits=1024)
    save_key(B_PUBLIC_KEY, pub)
    save_key(B_PRIVATE_KEY, priv)
    
    # Registrasi ke KDC
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_kdc:
            s_kdc.connect((KDC_HOST, KDC_PORT))
            n, e = pub
            s_kdc.sendall(f"REGISTER:B:{n}:{e}".encode('utf-8'))
            if s_kdc.recv(1024) == b'OK:REGISTERED':
                print("[B] Sukses mendaftar ke KDC.")
    except Exception as e:
        print(f"[B] Gagal daftar: {e}")
        exit()

b_private_key = load_key(B_PRIVATE_KEY)

# 2. Server Chat Standby
s_chat = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s_chat.bind((LISTEN_HOST, CHAT_PORT))
s_chat.listen()
print(f"\n[B] Menunggu koneksi A di {LISTEN_HOST}:{CHAT_PORT}...")

conn, addr = s_chat.accept()
with conn:
    print(f"[B] Terhubung dengan {addr}")
    
    # 3. Terima Tiket & Handshake
    print("[B] Menunggu Tiket & Handshake...")
    
    # A. Terima Tiket Session Key
    c_bytes_for_b = conn.recv(1024)
    c_int_for_b = int.from_bytes(c_bytes_for_b, 'big')
    des_key_bytes = crypter.rsa_decrypt_bytes(c_int_for_b, b_private_key, 8)
    des_key_str = des_key_bytes.decode('utf-8')
    print(f"[B] Session Key diterima: {des_key_str}")
    
    # B. Terima Public Key A
    enc_a_pub = conn.recv(4096).decode('utf-8')
    a_pub_str = crypter.des_decrypt_text(enc_a_pub, des_key_str)
    a_n, a_e = map(int, a_pub_str.split(':'))
    a_public_key = (a_n, a_e)
    print("[B] Public Key A diterima.")
    
    # C. Kirim Public Key B
    my_n, my_e = load_key(B_PUBLIC_KEY)
    enc_pubkey = crypter.des_encrypt_text(f"{my_n}:{my_e}", des_key_str)
    conn.sendall(enc_pubkey.encode('utf-8'))
    
    # 4. Mulai Thread Receiver (Pastikan 3 argumen!)
    receiver = threading.Thread(target=message_receiver, args=(conn, des_key_str, a_public_key), daemon=True)
    receiver.start()

    # 5. Loop Kirim Pesan
    try:
        while True:
            plaintext = input("Enter message (or 'exit'): ")
            if plaintext.lower() == 'exit': break
            
            # Sign & Encrypt
            signature = crypter.rsa_sign(plaintext, b_private_key)
            ciphertext = crypter.des_encrypt_text(plaintext, des_key_str)
            
            payload = f"{signature}||{ciphertext}"
            print(f"[Log B]: Sign -> {signature[:8]}... Encrypt -> {ciphertext}")
            conn.sendall(payload.encode('utf-8'))
            
    except Exception as e:
        print(f"[B] Error kirim: {e}")
# socket_client_b.py

import os
import time
import socket
import threading
import crypter as crypter

# --- Konfigurasi Jaringan (SESUAI GNS3) ---
KDC_HOST = '192.168.1.10' # IP KDC-Server
KDC_PORT = 9000           # Port KDC

LISTEN_HOST = '0.0.0.0'   # IP B untuk listening (192.168.1.12)
CHAT_PORT = 9001          # Port Chat (milik B)

# --- Nama File Kunci (Lokal di B) ---
B_PUBLIC_KEY = 'b_public.key'
B_PRIVATE_KEY = 'b_private.key'

# --- Fungsi Helper ---
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
            
            # Format: SIGNATURE || CIPHERTEXT
            if "||" in data:
                sig_hex, enc_msg = data.split("||")
                
                # 1. Dekripsi Pesan
                plaintext = crypter.des_decrypt_text(enc_msg, des_key)
                
                # 2. Verifikasi Tanda Tangan pakai PUBLIC KEY B
                is_valid = crypter.rsa_verify(plaintext, sig_hex, sender_pub_key)
                
                status = "✅ VALID" if is_valid else "❌ PALSU/CORRUPT"
                
                print(f"\n[Incoming from A] [{status}]: {plaintext}")
                print("Enter message (or 'exit'): ", end="", flush=True)
            else:
                print(f"\n[Raw Data Error]: {data}")

    except Exception as e:
        print(f"[B] Error: {e}")
        os._exit(1)

# --- Logika Utama Client B ---
print("--- Client B (Responder) ---")

# 1. Cek kunci RSA milik B
if not os.path.exists(B_PRIVATE_KEY):
    print("Membuat kunci RSA untuk B...")
    pub, priv = crypter.rsa_generate_keypair(bits=1024)
    save_key(B_PUBLIC_KEY, pub)
    save_key(B_PRIVATE_KEY, priv)
    print("Kunci B disimpan.")

    # --- REGISTRASI OTOMATIS via SOCKET ---
    print(f"Mendaftarkan kunci publik ke KDC di {KDC_HOST}:{KDC_PORT}...")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_kdc:
            s_kdc.connect((KDC_HOST, KDC_PORT))
            n, e = pub
            # Kirim perintah: REGISTER:ID:n:e
            cmd = f"REGISTER:B:{n}:{e}".encode('utf-8')
            s_kdc.sendall(cmd)
            resp = s_kdc.recv(1024)
            if resp == b'OK:REGISTERED':
                print("[B] Sukses mendaftar ke KDC.")
            else:
                print(f"[B] Gagal mendaftar: {resp.decode('utf-8')}")
    except Exception as e:
        print(f"[B] Error saat registrasi: {e}")
        exit() # Gagal daftar, jangan lanjut
# ---------------------------------------------------

print("Kunci RSA B ditemukan (atau baru saja dibuat).")
b_private_key = load_key(B_PRIVATE_KEY)

# 2. Siapkan Socket Server (B bertindak sebagai server untuk chat)
s_chat = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s_chat.bind((LISTEN_HOST, CHAT_PORT))
s_chat.listen()

print(f"\n[B] Server chat mendengarkan di {LISTEN_HOST}:{CHAT_PORT}...")
print("[B] Menunggu koneksi dari Client A...")

conn, addr = s_chat.accept()
with conn:
    print(f"[B] Menerima koneksi chat dari {addr}")
    
    # 3. Terima "Tiket" dari A (ini adalah pesan pertama)
    print("[B] Menunggu 'tiket' dari A...")
    c_bytes_for_b = conn.recv(1024) # Asumsi tiket < 1024 bytes
    
    if not c_bytes_for_b:
        print("[B] Gagal menerima tiket. Menutup.")
        exit()
        
    print("[B] Tiket diterima. Mendekripsi...")
    
    # 4. Dekripsi "Tiket" untuk mendapatkan kunci DES
    c_int_for_b = int.from_bytes(c_bytes_for_b, 'big')
    des_key_bytes = crypter.rsa_decrypt_bytes(c_int_for_b, b_private_key, 8)
    des_key_str = des_key_bytes.decode('utf-8')
    print(f"*** SUCCESS: Decrypted DES Key: '{des_key_str}' ***")

# 5. Mulai chat
    print("\n--- Koneksi Chat Terhubung ---")
    
    # === PERTUKARAN PUBLIC KEY ===
    print("[B] Bertukar kunci publik dengan A...")
    
    # Terima Public Key A dulu (karena A yang connect duluan)
    enc_a_pub = conn.recv(4096).decode('utf-8')
    a_pub_str = crypter.des_decrypt_text(enc_a_pub, des_key_str)
    a_n, a_e = map(int, a_pub_str.split(':'))
    a_public_key = (a_n, a_e)
    
    # Kirim Public Key B ke A
    my_n, my_e = load_key(B_PUBLIC_KEY)
    pubkey_str = f"{my_n}:{my_e}"
    enc_pubkey = crypter.des_encrypt_text(pubkey_str, des_key_str)
    conn.sendall(enc_pubkey.encode('utf-8'))
    
    print(f"[B] Kunci Publik A diterima.")
    # ==============================

    receiver = threading.Thread(target=message_receiver, args=(conn, des_key_str, a_public_key), daemon=True)
    receiver.start()

    try:
        while True:
            plaintext = input("Enter message (or 'exit'): ")
            if plaintext.lower() == 'exit':
                break
            
            # 1. Sign
            signature = crypter.rsa_sign(plaintext, b_private_key)
            # 2. Encrypt
            ciphertext = crypter.des_encrypt_text(plaintext, des_key_str)
            # 3. Send
            payload = f"{signature}||{ciphertext}"
            
            print(f"[Log B]: Sign & Encrypt -> {signature[:10]}... || {ciphertext}")
            conn.sendall(payload.encode('utf-8'))
            
    except Exception as e:
        print(f"[B] Error saat mengirim: {e}")
    finally:
        print("\nChat session ended.")
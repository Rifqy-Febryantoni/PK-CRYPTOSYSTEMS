# socket_client_a.py

import os
import time
import socket
import threading
import crypter as crypter

# --- Konfigurasi Jaringan (SESUAI GNS3) ---
KDC_HOST = '192.168.1.10' # IP KDC-Server
KDC_PORT = 9000           # Port KDC

CHAT_HOST = '192.168.1.12' # IP Client-B
CHAT_PORT = 9001           # Port Chat B

# --- Nama File Kunci (Lokal di A) ---
A_PUBLIC_KEY = 'a_public.key'
A_PRIVATE_KEY = 'a_private.key'

# --- Fungsi Helper ---
def save_key(filename, key_tuple):
    n, val = key_tuple
    with open(filename, 'w') as f: f.write(f"n = {n}\nkey_val = {val}\n")

def load_key(filename):
    if not os.path.exists(filename): return None
    key_data = {}
    with open(filename, 'r') as f: exec(f.read(), key_data)
    return (key_data['n'], key_data['key_val'])

# --- Thread Penerima Pesan Chat ---
def message_receiver(sock, des_key, sender_pub_key):
    print("\n[A] Penerima pesan aktif...")
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
                
                print(f"\n[Incoming from B] [{status}]: {plaintext}")
                print("Enter message (or 'exit'): ", end="", flush=True)
            else:
                print(f"\n[Raw Data Error]: {data}")

    except Exception as e:
        print(f"[A] Error: {e}")
        os._exit(1)

# --- Logika Utama Client A ---
print("--- Client A (Initiator) ---")

# 1. Cek kunci RSA milik A
if not os.path.exists(A_PRIVATE_KEY):
    print("Membuat kunci RSA untuk A...")
    pub, priv = crypter.rsa_generate_keypair(bits=1024)
    save_key(A_PUBLIC_KEY, pub)
    save_key(A_PRIVATE_KEY, priv)
    print("Kunci A disimpan.")
    
    # --- REGISTRASI OTOMATIS via SOCKET ---
    print(f"Mendaftarkan kunci publik ke KDC di {KDC_HOST}:{KDC_PORT}...")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_kdc:
            s_kdc.connect((KDC_HOST, KDC_PORT))
            n, e = pub
            # Kirim perintah: REGISTER:ID:n:e
            cmd = f"REGISTER:A:{n}:{e}".encode('utf-8')
            s_kdc.sendall(cmd)
            resp = s_kdc.recv(1024)
            if resp == b'OK:REGISTERED':
                print("[A] Sukses mendaftar ke KDC.")
            else:
                print(f"[A] Gagal mendaftar: {resp.decode('utf-8')}")
    except Exception as e:
        print(f"[A] Error saat registrasi: {e}")
    
    print("\nRegistrasi selesai. Jalankan lagi skrip ini untuk memulai chat.")
    exit() # Keluar setelah registrasi
# ---------------------------------------------------

# Jika skrip dijalankan lagi (kunci sudah ada):
print("Kunci RSA A ditemukan.")
a_private_key = load_key(A_PRIVATE_KEY)

# 2. Hubungi KDC untuk minta Kunci DES
print(f"\nMenghubungi KDC di {KDC_HOST}:{KDC_PORT} untuk minta kunci sesi...")
try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_kdc:
        s_kdc.connect((KDC_HOST, KDC_PORT))
        s_kdc.sendall(b"REQUEST:A:B") # Kirim perintah minta kunci

        # Terima 2 kunci dari KDC
        len_a_bytes = s_kdc.recv(4)
        len_a = int.from_bytes(len_a_bytes, 'big')
        c_bytes_for_a = s_kdc.recv(len_a)
        print("[A] Menerima kunci untuk A.")

        len_b_bytes = s_kdc.recv(4)
        len_b = int.from_bytes(len_b_bytes, 'big')
        c_bytes_for_b = s_kdc.recv(len_b) # Ini "Tiket" untuk B
        print("[A] Menerima 'tiket' untuk B.")
        
except socket.error as e:
    # Cek jika KDC bilang kunci belum ada
    if "KEYS_NOT_REGISTERED" in str(e):
         print("[A] GAGAL: KDC bilang kunci belum terdaftar. Pastikan Client B sudah mendaftar.")
    else:
        print(f"[A] Gagal menghubungi KDC: {e}")
    exit()
except Exception as e:
    print(f"[A] Gagal menghubungi KDC: {e}")
    exit()


# 3. Dekripsi kunci DES milik A
c_int_for_a = int.from_bytes(c_bytes_for_a, 'big')
des_key_bytes = crypter.rsa_decrypt_bytes(c_int_for_a, a_private_key, 8)
des_key_str = des_key_bytes.decode('utf-8')
print(f"*** SUCCESS: Decrypted DES Key: '{des_key_str}' ***")

# 4. Hubungi Client B untuk memulai chat
print(f"\nMenghubungi Client B di {CHAT_HOST}:{CHAT_PORT} untuk chat...")
try:
    s_chat = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_chat.connect((CHAT_HOST, CHAT_PORT))

    # 5. Kirim "Tiket" ke B sebagai pesan pertama
    print("[A] Mengirim 'tiket' terenkripsi ke B...")
    s_chat.sendall(c_bytes_for_b)
    
    # --- [BARU] HANDSHAKE PUBLIC KEY (Pertukaran Kunci Publik via DES) ---
    # Agar variable 'b_public_key' terdefinisi
    print("[A] Bertukar kunci publik dengan B untuk verifikasi tanda tangan...")
    
    # A. Kirim Public Key A ke B (Dienkripsi DES agar aman)
    my_n, my_e = load_key(A_PUBLIC_KEY)
    pubkey_str = f"{my_n}:{my_e}"
    enc_pubkey = crypter.des_encrypt_text(pubkey_str, des_key_str)
    s_chat.sendall(enc_pubkey.encode('utf-8'))
    
    # B. Terima Public Key B dari B
    enc_b_pub = s_chat.recv(4096).decode('utf-8')
    b_pub_str = crypter.des_decrypt_text(enc_b_pub, des_key_str)
    b_n, b_e = map(int, b_pub_str.split(':'))
    
    # INILAH DEFINISI VARIABEL YANG HILANG TADI:
    b_public_key = (b_n, b_e) 
    print(f"[A] Kunci Publik B diterima & diverifikasi.")
    # ---------------------------------------------------------------------

    # 6. Mulai chat
    print("\n--- Koneksi Chat Terhubung ---")
    
    # Sekarang 'b_public_key' sudah ada isinya, jadi thread ini tidak akan error
    receiver = threading.Thread(target=message_receiver, args=(s_chat, des_key_str, b_public_key), daemon=True)
    receiver.start()

    while True:
        plaintext = input("Enter message to send (or 'exit'): ")
        if plaintext.lower() == 'exit':
            break
        
        # --- [BARU] LOGIKA TANDA TANGAN (SIGNING) ---
        # 1. Buat Tanda Tangan dari plaintext pakai Private Key A
        signature = crypter.rsa_sign(plaintext, a_private_key)
        
        # 2. Enkripsi Pesan pakai DES
        ciphertext_hex = crypter.des_encrypt_text(plaintext, des_key_str)
        
        # 3. Gabungkan: SIGNATURE || CIPHERTEXT
        payload = f"{signature}||{ciphertext_hex}"
        
        print(f"[Log A]: Sign & Encrypt -> {signature[:10]}... || {ciphertext_hex}")
        s_chat.sendall(payload.encode('utf-8'))

except Exception as e:
    print(f"[A] Gagal terhubung ke B: {e}")
finally:
    if 's_chat' in locals():
        s_chat.close()
    print("\nChat session ended.")
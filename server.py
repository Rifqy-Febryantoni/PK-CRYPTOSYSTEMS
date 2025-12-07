# socket_server_kdc.py

import os
import time
import random
import string
import socket
import crypter as crypter

# --- Konfigurasi Jaringan ---
HOST = '0.0.0.0'  # Dengarkan di semua IP (termasuk 192.168.1.10)
KDC_PORT = 9000     # Port untuk layanan KDC

# --- Nama File Kunci (Lokal di server) ---
KDC_PRIVATE_KEY = 'kdc_private.key'
KDC_PUBLIC_KEY = 'kdc_public.key'

# --- Database Kunci Publik Klien (Disimpan di Memori) ---
client_public_keys = {}

# --- Fungsi Helper untuk load/save kunci ---
def save_key(filename, key_tuple):
    n, val = key_tuple
    with open(filename, 'w') as f: f.write(f"n = {n}\nkey_val = {val}\n")

def load_key(filename):
    if not os.path.exists(filename): return None
    key_data = {}
    with open(filename, 'r') as f: exec(f.read(), key_data)
    return (key_data['n'], key_data['key_val'])

# --- Logika Utama Server KDC ---
print("--- KDC Server ---")

# 1. Load/Generate kunci RSA milik KDC
if not os.path.exists(KDC_PRIVATE_KEY):
    print("Membuat kunci RSA untuk KDC...")
    pub, priv = crypter.rsa_generate_keypair(bits=1024)
    save_key(KDC_PUBLIC_KEY, pub)
    save_key(KDC_PRIVATE_KEY, priv)
    print("Kunci KDC disimpan.")
kdc_private_key = load_key(KDC_PRIVATE_KEY)

# 2. Siapkan Socket Server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, KDC_PORT))
s.listen()

print(f"\n[KDC] Server mendengarkan di {HOST}:{KDC_PORT}...")

while True:
    conn, addr = s.accept()
    print(f"\n[KDC] Menerima koneksi dari {addr}")
    
    with conn:
        try:
            # Terima data (buat buffer lebih besar untuk kunci)
            data = conn.recv(4096)
            if not data:
                continue

            # Parsing perintah (misal: "REGISTER:A:n:e" atau "REQUEST:A:B")
            parts = data.decode('utf-8').split(':', 3)
            command = parts[0]

            if command == 'REGISTER':
                client_id = parts[1]
                n = int(parts[2])
                e = int(parts[3])
                
                # Simpan kunci publik klien ke memori
                client_public_keys[client_id] = (n, e)
                print(f"[KDC] Sukses mendaftarkan kunci publik untuk '{client_id}'.")
                conn.sendall(b'OK:REGISTERED')

            elif command == 'REQUEST':
                id_a = parts[1]
                id_b = parts[2]
                print(f"[KDC] Menerima permintaan kunci dari '{id_a}' untuk '{id_b}'.")

                # Cek apakah kedua kunci sudah terdaftar
                if id_a in client_public_keys and id_b in client_public_keys:
                    a_public_key = client_public_keys[id_a]
                    b_public_key = client_public_keys[id_b]
                    
                    # 1. Buat kunci DES 8-byte
                    des_key_str = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
                    des_key_bytes = des_key_str.encode('utf-8')
                    print(f"[KDC] Membuat kunci DES baru: '{des_key_str}'")

                    # 2. Enkripsi untuk A dan B
                    c_int_for_a = crypter.rsa_encrypt_bytes(des_key_bytes, a_public_key)
                    c_int_for_b = crypter.rsa_encrypt_bytes(des_key_bytes, b_public_key)

                    # 3. Ubah ke bytes
                    key_byte_len = (a_public_key[0].bit_length() + 7) // 8
                    c_bytes_for_a = c_int_for_a.to_bytes(key_byte_len, 'big')
                    c_bytes_for_b = c_int_for_b.to_bytes(key_byte_len, 'big')

                    # 4. Kirim kedua kunci ke Client A
                    print("[KDC] Mengirim kunci terenkripsi ke A...")
                    conn.sendall(len(c_bytes_for_a).to_bytes(4, 'big'))
                    conn.sendall(c_bytes_for_a)
                    conn.sendall(len(c_bytes_for_b).to_bytes(4, 'big'))
                    conn.sendall(c_bytes_for_b)
                    print("[KDC] Pengiriman selesai.")
                
                else:
                    print("[KDC] GAGAL: Salah satu atau kedua kunci belum terdaftar.")
                    conn.sendall(b'ERROR:KEYS_NOT_REGISTERED')

            else:
                print(f"[KDC] Perintah tidak dikenal: {data}")
                conn.sendall(b'ERROR:UNKNOWN_COMMAND')

        except Exception as e:
            print(f"[KDC] Terjadi Error: {e}")
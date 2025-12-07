# socket_server_kdc.py
import os
import random
import string
import socket
import crypter

# --- Konfigurasi ---
HOST = '0.0.0.0'
KDC_PORT = 9000

KDC_PRIVATE_KEY = 'kdc_private.key'
KDC_PUBLIC_KEY = 'kdc_public.key'

# Memori penyimpanan Public Key Klien
client_public_keys = {}

def save_key(filename, key_tuple):
    n, val = key_tuple
    with open(filename, 'w') as f: f.write(f"n = {n}\nkey_val = {val}\n")

def load_key(filename):
    if not os.path.exists(filename): return None
    key_data = {}
    with open(filename, 'r') as f: exec(f.read(), key_data)
    return (key_data['n'], key_data['key_val'])

print("--- KDC Server ---")
if not os.path.exists(KDC_PRIVATE_KEY):
    print("Membuat Kunci KDC...")
    pub, priv = crypter.rsa_generate_keypair(1024)
    save_key(KDC_PUBLIC_KEY, pub)
    save_key(KDC_PRIVATE_KEY, priv)
kdc_private_key = load_key(KDC_PRIVATE_KEY)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, KDC_PORT))
s.listen()
print(f"[KDC] Listening on port {KDC_PORT}...")

while True:
    conn, addr = s.accept()
    with conn:
        try:
            data = conn.recv(4096)
            if not data: continue
            
            parts = data.decode('utf-8').split(':', 3)
            command = parts[0]
            
            if command == 'REGISTER':
                client_id = parts[1]
                n, e = int(parts[2]), int(parts[3])
                client_public_keys[client_id] = (n, e)
                print(f"[KDC] Registered: {client_id}")
                conn.sendall(b'OK:REGISTERED')
                
            elif command == 'REQUEST':
                id_a, id_b = parts[1], parts[2]
                print(f"[KDC] Request: {id_a} -> {id_b}")
                
                if id_a in client_public_keys and id_b in client_public_keys:
                    # Buat Session Key (DES)
                    des_key_str = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
                    des_key_bytes = des_key_str.encode('utf-8')
                    
                    # Encrypt untuk A & B
                    c_int_a = crypter.rsa_encrypt_bytes(des_key_bytes, client_public_keys[id_a])
                    c_int_b = crypter.rsa_encrypt_bytes(des_key_bytes, client_public_keys[id_b])
                    
                    # Ubah ke bytes (size 128 bytes for 1024 bit key)
                    c_bytes_a = c_int_a.to_bytes(128, 'big')
                    c_bytes_b = c_int_b.to_bytes(128, 'big')
                    
                    conn.sendall(len(c_bytes_a).to_bytes(4, 'big'))
                    conn.sendall(c_bytes_a)
                    conn.sendall(len(c_bytes_b).to_bytes(4, 'big'))
                    conn.sendall(c_bytes_b)
                    print(f"[KDC] Sent keys for {des_key_str}")
                else:
                    print("[KDC] Error: Salah satu client belum daftar.")
                    conn.sendall(b'ERROR:KEYS_NOT_REGISTERED')
        except Exception as e:
            print(f"[KDC] Error: {e}")
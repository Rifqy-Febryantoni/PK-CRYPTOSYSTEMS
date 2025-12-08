import os, socket, threading, crypter

# Konfigurasi
KDC_HOST = '192.168.1.10'
KDC_PORT = 9000
LISTEN_HOST = '0.0.0.0'
CHAT_PORT = 9001

B_KEY_FILES = ('b_public.key', 'b_private.key')

def save_key(f, k): 
    with open(f, 'w') as file: file.write(f"n = {k[0]}\nkey_val = {k[1]}\n")
def load_key(f):
    d = {}
    with open(f, 'r') as file: exec(file.read(), d)
    return (d['n'], d['key_val'])

# PENERIMA PESAN
def receiver_thread(sock, des_key, sender_pub):
    print("\n[B] Chat Ready. Mode: STRICT (Block Invalid Signatures)...")
    try:
        while True:
            data = sock.recv(4096).decode('utf-8')
            if not data: break
            
            # 1. LOG TRANSPARANSI
            if "||" in data:
                sig_hex, enc_msg = data.split("||")
                print(f"\n[Log Payload Received]:")
                print(f"   > Signature (RSA): {sig_hex[:15]}...")
                print(f"   > Ciphertext (DES): {enc_msg}")
                
                # 2. DEKRIPSI (DES)
                plaintext = crypter.des_decrypt_text(enc_msg, des_key)
                
                # 3. VERIFIKASI (RSA)
                is_valid = crypter.rsa_verify(plaintext, sig_hex, sender_pub)
                
                # 4. KEPUTUSAN (STRICT MODE)
                if is_valid:
                    # HANYA TAMPILKAN JIKA VALID
                    print(f"[Incoming from A] [✅ VALID]: {plaintext}")
                else:
                    # SEMBUNYIKAN JIKA PALSU
                    print(f"[⛔ SECURITY BLOCK]: Pesan diblokir! Tanda tangan digital PALSU.")
                
                print("Send (or exit): ", end="", flush=True)
            else:
                 print(f"[Raw Data]: {data}")
                 
    except Exception as e:
        print(f"Error receiver: {e}")
        os._exit(1)

# SETUP
print("--- Client B (Responder) ---")
if not os.path.exists(B_KEY_FILES[1]):
    pub, priv = crypter.rsa_generate_keypair(1024)
    save_key(B_KEY_FILES[0], pub); save_key(B_KEY_FILES[1], priv)

b_priv = load_key(B_KEY_FILES[1])
b_pub = load_key(B_KEY_FILES[0])

# AUTO REGISTER
try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((KDC_HOST, KDC_PORT))
        s.sendall(f"REGISTER:B:{b_pub[0]}:{b_pub[1]}".encode())
        if s.recv(1024) == b'OK:REGISTERED': print("[B] Registered to KDC.")
except: pass

# SERVER CHAT
serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serv.bind((LISTEN_HOST, CHAT_PORT))
serv.listen()
print(f"[B] Waiting for A on port {CHAT_PORT}...")

conn, addr = serv.accept()
with conn:
    print(f"[B] Connected to {addr}")
    
    # Terima Tiket & Handshake
    c_bytes = conn.recv(1024)
    if len(c_bytes) == 0: exit()
    c_int = int.from_bytes(c_bytes, 'big')
    des_key = crypter.rsa_decrypt_bytes(c_int, b_priv, 8).decode()
    print(f"[B] Session Key: {des_key}")
    
    # Handshake Public Key
    enc_a = conn.recv(4096).decode()
    a_str = crypter.des_decrypt_text(enc_a, des_key)
    an, ae = map(int, a_str.split(':'))
    a_pub = (an, ae)
    
    conn.sendall(crypter.des_encrypt_text(f"{b_pub[0]}:{b_pub[1]}", des_key).encode())
    print("[B] Handshake Complete.")
    
    threading.Thread(target=receiver_thread, args=(conn, des_key, a_pub), daemon=True).start()
    
    while True:
        msg = input("Send (or exit): ")
        if msg == 'exit': break
        sig = crypter.rsa_sign(msg, b_priv)
        enc = crypter.des_encrypt_text(msg, des_key)
        print(f"\n[Log Payload Sending]:")
        print(f"   > Signature: {sig[:10]}...")
        print(f"   > Ciphertext: {enc}")
        conn.sendall(f"{sig}||{enc}".encode())
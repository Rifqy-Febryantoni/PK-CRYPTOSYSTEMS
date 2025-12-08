import os, socket, threading, sys, crypter

# Konfigurasi
KDC_HOST = '192.168.1.10'
KDC_PORT = 9000
CHAT_HOST = '192.168.1.12'
CHAT_PORT = 9001

A_KEY_FILES = ('a_public.key', 'a_private.key')

def save_key(f, k): 
    with open(f, 'w') as file: file.write(f"n = {k[0]}\nkey_val = {k[1]}\n")
def load_key(f):
    d = {}
    with open(f, 'r') as file: exec(file.read(), d)
    return (d['n'], d['key_val'])

# PENERIMA PESAN
def receiver_thread(sock, des_key, sender_pub):
    print("\n[A] Chat Ready. Mode: STRICT (Block Invalid Signatures)...")
    try:
        while True:
            data = sock.recv(4096).decode('utf-8')
            if not data: break
            
            if "||" in data:
                sig_hex, enc_msg = data.split("||")
                print(f"\n[Log Payload Received]:")
                print(f"   > Signature: {sig_hex[:15]}...")
                print(f"   > Ciphertext: {enc_msg}")
                
                plaintext = crypter.des_decrypt_text(enc_msg, des_key)
                is_valid = crypter.rsa_verify(plaintext, sig_hex, sender_pub)
                
                if is_valid:
                    print(f"[Incoming from B] [✅ VALID]: {plaintext}")
                else:
                    print(f"[⛔ SECURITY BLOCK]: Pesan diblokir! Tanda tangan digital PALSU.")
                    print(f"(Isi pesan disembunyikan sistem)")
                
                print("Send (or exit): ", end="", flush=True)
    except: os._exit(1)

# SETUP
print("--- Client A ---")
if not os.path.exists(A_KEY_FILES[1]):
    pub, priv = crypter.rsa_generate_keypair(1024)
    save_key(A_KEY_FILES[0], pub); save_key(A_KEY_FILES[1], priv)

a_priv = load_key(A_KEY_FILES[1])
a_pub = load_key(A_KEY_FILES[0])

# AUTO REGISTER
try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((KDC_HOST, KDC_PORT))
        s.sendall(f"REGISTER:A:{a_pub[0]}:{a_pub[1]}".encode())
        if s.recv(1024) == b'OK:REGISTERED': print("[A] Registered to KDC.")
except: pass

# REQUEST KEY & CONNECT
try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as kdc:
        kdc.connect((KDC_HOST, KDC_PORT))
        kdc.sendall(b"REQUEST:A:B")
        
        len_a = int.from_bytes(kdc.recv(4), 'big')
        c_bytes_a = kdc.recv(len_a)
        len_b = int.from_bytes(kdc.recv(4), 'big')
        c_bytes_b = kdc.recv(len_b)
        
    c_int_a = int.from_bytes(c_bytes_a, 'big')
    des_key = crypter.rsa_decrypt_bytes(c_int_a, a_priv, 8).decode()
    print(f"[A] Session Key: {des_key}")
    
    chat = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    chat.connect((CHAT_HOST, CHAT_PORT))
    
    # 1. Kirim Tiket
    chat.sendall(c_bytes_b)
    
    # 2. Handshake Public Key
    chat.sendall(crypter.des_encrypt_text(f"{a_pub[0]}:{a_pub[1]}", des_key).encode())
    enc_b = chat.recv(4096).decode()
    b_str = crypter.des_decrypt_text(enc_b, des_key)
    bn, be = map(int, b_str.split(':'))
    b_pub = (bn, be)
    print("[A] Handshake Complete.")
    
    threading.Thread(target=receiver_thread, args=(chat, des_key, b_pub), daemon=True).start()
    
    HACKER = "--hack" in sys.argv
    if HACKER: print("\n[⚠️ HACKER MODE] Signatures will be FAKE!")
    
    while True:
        msg = input("Send (or exit): ")
        if msg == 'exit': break
        
        # 1. Sign (Asli atau Palsu)
        sig = crypter.rsa_sign(msg, a_priv)
        if HACKER: sig = "deadbeef" * 4 # FAKE SIG
        
        # 2. Encrypt
        enc = crypter.des_encrypt_text(msg, des_key)
        
        # 3. Kirim
        print(f"[Log Sending]: {sig[:10]}... || {enc}")
        chat.sendall(f"{sig}||{enc}".encode())
        
except Exception as e: print(f"Error: {e}")
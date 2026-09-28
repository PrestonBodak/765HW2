import os
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac

HEADER_FORMAT = ">BBQBI"
IV_FORMAT = ">QQ"

class RecordManager:
    def __init(self):
        self.tag = None
        self.ciphertext = ""
        self.header = None
        self.sequence = 0
        self.key_iv_pairs = {}
        return
    
    def seal(self, K_enc, K_mac, iv, header, plaintext):
        #Verify IV not reused for a key
        if self.key_iv_pairs[K_enc] == iv or self.key_iv_pairs[K_mac] == iv:
            raise ValueError("IV cannot be reused for a key.")

        self.key_iv_pairs[K_enc] = iv
        self.key_iv_pairs[K_mac] = iv

        #Extract sequence number and verify it is next
        session_id, iv_sequence = struct.unpack(IV_FORMAT, iv)

        if iv_sequence != (self.sequence + 1):
            raise ValueError("Provided sequence unexpected.")

        #Encrypt
        cipher = Cipher(algorithms.AES(K_enc), modes.CTR(iv))
        encryptor = cipher.encryptor()
        self.ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        #Unpack and check header
        version, direction, h_sequence, message_type, ciphertext_length = struct.unpack(HEADER_FORMAT, header)
        if h_sequence != iv_sequence:
            raise ValueError("Header and IV sequence numbers do not match")

        if direction != ord("I"):
            raise ValueError("Incorrect direction for a seal")
        
        if len(self.ciphertext) != ciphertext_length:
            raise ValueError("Ciphertext length mismatch.")
        
        self.sequence = iv_sequence

        #Encrypt-then-MAC
        h = hmac.HMAC(K_mac, hashes.SHA256())
        h.update(header + iv + self.ciphertext)
        self.tag = h.finalize()
        self.header = header
        return

    def open_record(self):
        return

rm = RecordManager()
K_enc = os.urandom(32)
K_mac = os.urandom(32)
iv = struct.pack(IV_FORMAT, os.urandom(8), 0)
plaintext = "Hello there!"
header = struct.pack(HEADER_FORMAT, 1, ord("I"), 0, 125, len(plaintext))


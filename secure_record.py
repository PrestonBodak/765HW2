import os
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, constant_time

HEADER_FORMAT = ">BBQBI"
IV_FORMAT = ">QQ"

class RecordManager:
    def __init__(self):
        self.tag = None
        self.ciphertext = ""
        self.header = None
        self.sequence = 0
        self.key_iv_pairs = {}
        return
    
    def seal(self, K_enc, K_mac, iv, header, plaintext):
        #Verify IV not reused for a key
        try:
            if self.key_iv_pairs[K_enc] == iv or self.key_iv_pairs[K_mac] == iv:
                raise ValueError("IV cannot be reused for a key.")
        except KeyError:
            self.key_iv_pairs[K_enc] = iv
            self.key_iv_pairs[K_mac] = iv

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

    def open_record(self, K_enc, h, iv, s_tag):

        #Verify HMAC before decrypting
        h.verify(self.tag)

        #Use constant-time MAC verification for tags
        if not (constant_time.bytes_eq(s_tag, self.tag)):
            raise ValueError("Sender tag and sealed tag do not match.")

        #Decrypt record, update direction, and return
        version, direction, h_sequence, message_type, ciphertext_length = struct.unpack(HEADER_FORMAT, self.header)
        header_out = struct.pack(HEADER_FORMAT, version, ord("O"), h_sequence, message_type, ciphertext_length)
        cipher = Cipher(algorithms.AES(K_enc), modes.CTR(iv))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(self.ciphertext) + decryptor.finalize()
        return header_out, plaintext

#Sender
rm = RecordManager()
K_enc = os.urandom(32)
K_mac = os.urandom(32)
iv = struct.pack(IV_FORMAT, int.from_bytes(os.urandom(8), byteorder="big"), 1)
plaintext = b"Hello there!"
header = struct.pack(HEADER_FORMAT, 1, ord("I"), 1, 125, len(plaintext))

#Store a record
rm.seal(K_enc, K_mac, iv, header, plaintext)

#Generate auth data and open record
h = hmac.HMAC(K_mac, hashes.SHA256())
cipher = Cipher(algorithms.AES(K_enc), modes.CTR(iv))
encryptor = cipher.encryptor()
ciphertext = encryptor.update(plaintext) + encryptor.finalize()
h.update(header + iv + ciphertext)
h_copy = h.copy()
tag = h.finalize()
data = rm.open_record(K_enc, h_copy, iv, tag)

print("Retrieved:\n{}\n{}".format(struct.unpack(HEADER_FORMAT, data[0]), data[1].decode()))
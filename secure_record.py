import os
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, constant_time, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

HEADER_FORMAT = ">BBQBI"
IV_FORMAT = ">QQ"

class Session:
    def __init__(self, identity, session_id=0):
        self.identity = identity
        self.session_id = session_id
        self.rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        self.rsa_public_key = self.rsa_private_key.public_key()
        self.signature = None
        with open("./ffdhe3072.pem", "rb") as param_file:
            self.dh_parameters = serialization.load_pem_parameters(param_file.read())
        self.dh_private_key = self.dh_parameters.generate_private_key()
        self.dh_public_key = self.dh_private_key.public_key()
        self.dh_shared_key = None
        self.z = None
        self.nonce = os.urandom(16)
        self.open = True
        self.sequence = 0
        return

    def generateSignature(self, message):
        if not open:
            raise Exception("Session is closed due to failed signature verification.")

        print(self.identity + " generating a signature...")
        self.signature = self.rsa_private_key.sign(message, 
                                                   padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), 
                                                   hashes.SHA256())
        return self.signature

    def verifySignature(self, publicKey, signature, message):
        if not open:
            raise Exception("Session is closed due to failed signature verification.")

        print(self.identity + " verifying a signature...")
        try:
            publicKey.verify(signature,
                             message,
                             padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                             hashes.SHA256())
        except Exception as e:
            print("Invalid signature! {}".format(e))
            self.open = False
        
        return

    def dhExchange(self, publicKey):
        if not open:
            raise Exception("Session is closed due to failed signature verification.")

        print(self.identity + " generating a shared DH secret...")
        self.dh_shared_key = self.dh_private_key.exchange(publicKey)
        self.z = ((self.dh_shared_key.decode("latin-1")).rjust(384, "0")).encode("latin-1")
        return

    def generateKeys(self, transcript, destination_identifier):
        if not open:
            raise Exception("Session is closed due to failed signature verification.")

        digest = hashes.Hash(hashes.SHA256())
        digest.update(transcript)
        th = digest.finalize()
        digest = hashes.Hash(hashes.SHA256())
        digest.update(b"CSCE465-KDF-v1" + self.z + th)
        K_master = digest.finalize()
        
        h = hmac.HMAC(K_master, hashes.SHA256())
        h.update(("{}-to-{} encryption".format(self.identity, destination_identifier)).encode() + th)
        self.K_out_enc = h.finalize()

        h = hmac.HMAC(K_master, hashes.SHA256())
        h.update(("{}-to-{} MAC".format(self.identity, destination_identifier)).encode() + th)
        self.K_out_mac = h.finalize()

        h = hmac.HMAC(K_master, hashes.SHA256())
        h.update(("{}-to-{} encryption".format(destination_identifier, self.identity)).encode() + th)
        self.K_in_enc = h.finalize()

        h = hmac.HMAC(K_master, hashes.SHA256())
        h.update(("{}-to-{} MAC".format(destination_identifier, self.identity)).encode() + th)
        self.K_in_mac = h.finalize()

        #print("{} generated the following keys:\nK_master \nK_enc \nK_mac \nsession_id \n".format(self.identity))
        return

    '''
    TODO
    - Finish seal and open_record
    - Establish purpose for direction and its relationship to K_out and K_in
    - Add dueling sequence numbers for direction and update them on tx/rx
    - Parties verify version no.
    - Check packets for all other requirements in task 3 guidelines
    '''

    def seal(self, direction, sequence, message_type, plaintext):
        #Build IV
        iv = struct.pack(IV_FORMAT, (self.session_id).to_bytes(8, "big") + (sequence).to_bytes(8, "big"))

        #Encrypt message with outgoing key
        cipher = Cipher(algorithms.AES(self.K_out_enc), modes.CTR(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        #Build header -> version, direction, sequence, m_type, ct length
        header = struct.pack(HEADER_FORMAT, 25, direction, sequence, message_type, len(ciphertext))

        #Build tag w/ encrypt-then-MAC
        h = hmac.HMAC(self.K_out_mac, hashes.SHA256())
        h.update(header + iv + ciphertext)
        tag = h.finalize()

        # Return header || ct || tag
        return header, ciphertext, tag

    def open_record(self, header, body, tag, source):
        #Unpack header
        version, direction, h_sequence, message_type, ciphertext_length = struct.unpack(HEADER_FORMAT, self.header)

        #Verify session_id and sequence before re-generating IV

        #Verify HMAC before decrypting

        #Build IV
        iv = struct.pack(IV_FORMAT, (self.session_id).to_bytes(8, "big") + (h_sequence).to_bytes(8, "big"))

        #Decrypt message with incoming key and return plaintext
        cipher = Cipher(algorithms.AES(self.K_in_enc), modes.CTR(iv))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(plaintext) + decryptor.finalize()
        return plaintext

    def send(self, header, body, tag, destination):
        #Call receive function of destination session object
        destination.receive(header, body, tag, self)
        return

    def receive(self, header, body, tag, source):
        #Call self.open_record
        self.open_record(header, body, tag, source)
        return




'''
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
'''

# REPLACE

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
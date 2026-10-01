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
        self.tx_sequence = 0
        self.rx_sequence = 0
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
        
        return

    def seal(self, direction, message_type, plaintext):
        #Build IV
        iv = struct.pack(IV_FORMAT, self.session_id, self.tx_sequence)

        #Encrypt message with outgoing key
        cipher = Cipher(algorithms.AES(self.K_out_enc), modes.CTR(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        #Build header -> version, direction, sequence, m_type, ct length
        header = struct.pack(HEADER_FORMAT, 25, direction, self.tx_sequence, message_type, len(ciphertext))
        self.tx_sequence += 1

        #Build tag w/ encrypt-then-MAC
        h = hmac.HMAC(self.K_out_mac, hashes.SHA256())
        h.update(header + iv + ciphertext)
        tag = h.finalize()

        # Return header || ct || tag
        print("{} sealed plaintext: {}".format(self.identity, plaintext.decode()))
        return header, ciphertext, tag

    def open_record(self, header, body, tag, source_id):
        #Unpack header
        version, direction, h_sequence, message_type, ciphertext_length = struct.unpack(HEADER_FORMAT, header)

        if version != 25:
            raise ValueError("open_record() incorrect version number")

        if self.identity == "Node" and direction != 1:
            raise ValueError("open_record() from Node expects direction = 1")
        elif self.identity == "Gateway" and direction != 0:
            raise ValueError("open_record() from Gateway expects direction = 0")

        #Verify sequence before re-generating IV
        if h_sequence != self.rx_sequence:
            raise ValueError("open_record() mismatch of received sequence vs expected sequence")
        else:
            self.rx_sequence += 1

        #Build IV
        iv = struct.pack(IV_FORMAT, self.session_id, h_sequence)

        #Verify HMAC before decrypting
        h = hmac.HMAC(self.K_in_mac, hashes.SHA256())
        h.update(header + iv + body)
        h_constant = h.copy()
        h.verify(tag)

        #Constant-time MAC verification
        if not constant_time.bytes_eq(h_constant.finalize(), tag):
            raise ValueError("open_record() could not verify MAC in constant-time")


        #Decrypt message with incoming key and return plaintext
        cipher = Cipher(algorithms.AES(self.K_in_enc), modes.CTR(iv))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(body) + decryptor.finalize()
        print("{} decrypted ciphertext to reveal message: {}".format(self.identity, plaintext))
        return plaintext

    def send(self, header, body, tag, destination):
        print("{} sending a message to {}...".format(self.identity, destination.identity))
        #Call receive function of destination session object
        destination.receive(header, body, tag, self.identity)
        return

    def receive(self, header, body, tag, source_id):
        print("{} receiving a message from {}...".format(self.identity, source_id))
        #Call self.open_record
        self.open_record(header, body, tag, source_id)
        return

gateway = Session("Gateway", 33)
node = Session("Node", 33)
#Transcript = Protocol Label Length || Protocol Label || Group Length || Group Identifier || Gateway Identity Length || Gateway Identity || Node Identity Length || Node Identity
# || Gateway Public Key Length || Gateway Public Key || Node Public Key Length || Node Public Key || Gateway Nonce Length || Gateway Nonce || Node Nonce Length || Node Nonce
protocol = b"CSCE465-HS-v2"
group = b"ffdhe3072"
TRANSCRIPT_FORMAT = b">i13si9si7si4si384si384si16si16s"
transcript = struct.pack(TRANSCRIPT_FORMAT, 
                         len(protocol), 
                         protocol, 
                         len(group), 
                         group, 
                         len(gateway.identity), 
                         gateway.identity.encode(), 
                         len(node.identity), 
                         node.identity.encode(), 
                         384, 
                         ((gateway.dh_public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("latin-1")).rjust(384, "0")).encode("latin-1"), 
                         384, 
                         ((node.dh_public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("latin-1")).rjust(384, "0")).encode("latin-1"), 
                         16, 
                         gateway.nonce, 
                         16, 
                         node.nonce)

#Sign with private keys
#Verify each other's signature with public keys
gateway.verifySignature(node.rsa_public_key, node.generateSignature(b"Node" + transcript), b"Node" + transcript)
node.verifySignature(gateway.rsa_public_key, gateway.generateSignature(b"Gateway" + transcript), b"Gateway" + transcript)

#Exchange public keys and generate shared secret
gateway.dhExchange(node.dh_public_key)
node.dhExchange(gateway.dh_public_key)

gateway.generateKeys(transcript, "Node")
node.generateKeys(transcript, "Gateway")

gateway.send(*(gateway.seal(1, 5, b"Can you hear me?")), node)
node.send(*(node.seal(0, 5, b"Yes I can!")), gateway)
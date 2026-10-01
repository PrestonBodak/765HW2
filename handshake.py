import os
import struct
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

class Session:
    def __init__(self, identity):
        self.identity = identity
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

    def generateKeys(self, transcript, destination):
        if not open:
            raise Exception("Session is closed due to failed signature verification.")

        digest = hashes.Hash(hashes.SHA256())
        digest.update(transcript)
        th = digest.finalize()
        digest = hashes.Hash(hashes.SHA256())
        digest.update(b"CSCE465-KDF-v1" + self.z + th)
        K_master = digest.finalize()
        
        h = hmac.HMAC(K_master, hashes.SHA256())
        h.update(("{}-to-{} encryption".format(self.identity, destination)).encode() + th)
        K_enc = h.finalize()

        h = hmac.HMAC(K_master, hashes.SHA256())
        h.update(("{}-to-{} MAC".format(self.identity, destination)).encode() + th)
        K_mac = h.finalize()

        h = hmac.HMAC(K_master, hashes.SHA256())
        h.update(b"session identifier" + th)
        session_id = h.finalize()

        print("{} generated the following keys:\nK_master \nK_enc \nK_mac \nsession_id \n".format(self.identity))
        return

gateway = Session("Gateway")
node = Session("Node")
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
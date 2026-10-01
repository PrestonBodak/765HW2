import struct
from cryptography.hazmat.primitives import serialization
from session import Session

HEADER_FORMAT = ">BBQBI"
IV_FORMAT = ">QQ"

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

print("Beginning test 3 - modified authenticated header")

#Sign with private keys
#Verify each other's signature with public keys
gateway.verifySignature(node.rsa_public_key, node.generateSignature(b"Node" + transcript), b"Node" + transcript)
node.verifySignature(gateway.rsa_public_key, gateway.generateSignature(b"Gateway" + transcript), b"Gateway" + transcript)

#Exchange public keys and generate shared secret
gateway.dhExchange(node.dh_public_key)
node.dhExchange(gateway.dh_public_key)

gateway.generateKeys(transcript, "Node")
node.generateKeys(transcript, "Gateway")

#Information that is transmitted on a public channel to the receiver
header, ciphertext, tag = gateway.seal(1, 5, b"Can you hear me?")

#Malware changes the header before it is sent
modified_header = struct.pack(HEADER_FORMAT, 8, 2, 5, 9, 3)
gateway.send(modified_header, ciphertext, tag, node)
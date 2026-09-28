import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = os.urandom(16)
iv  = os.urandom(16)

cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
encryptor = cipher.encryptor()

plaintext = b"{\"action\":\"READ\",\"path\":\"notes.txt\"}"
ciphertext = encryptor.update(plaintext) + encryptor.finalize()

#Convert ciphertext to hex for tampering, 1 byte = 2 hex characters
print("Original encryption:\nPlaintext: {}\nCiphertext (hex): {}\n".format(plaintext, ciphertext.hex()))

#Plaintext is 36 bytes long, READ is found at character/byte indices 11:14
print("Extract target bytes:\nPlaintext target: {}\nCiphertext (hex) target: {}\n".format(plaintext[11:15], ciphertext.hex()[22:30]))

#Change ciphertext at target location to 0s to recover key
blank_ciphertext = bytes.fromhex(ciphertext.hex()[:22] + "00000000"+ ciphertext.hex()[30:])
decryptor = cipher.decryptor()
target_key = (decryptor.update(blank_ciphertext) + decryptor.finalize()).hex()[22:30]
#print("Extract key and modify CT + PT:\nTarget key bits: {}".format(target_key))

#Write over location of READ in the ciphertext
#XOR desired new target with recovered key and insert into ciphertext
encoded_target = ((int.from_bytes("HACK".encode("unicode_escape"), byteorder="big")) ^ (int.from_bytes(bytes.fromhex(target_key), byteorder="big"))).to_bytes(4, byteorder="big").hex()
#To modify the target to a specific equal-length value, encoded_target can be used
tampered_ciphertext = bytes.fromhex(ciphertext.hex()[:22] + b"HACK".hex() + ciphertext.hex()[30:])

print("Ciphertext (hex) with target inserted: {}\nNote the new sequence {} where READ used to be in the original ciphertext!".format(tampered_ciphertext.hex(), tampered_ciphertext.hex()[22:30]))

#Decrypt to show tampered plaintext
decryptor = cipher.decryptor()
recovered = (decryptor.update(tampered_ciphertext) + decryptor.finalize()).decode("unicode_escape")
print("Recovered (tampered) plaintext: {}".format(recovered))

#Replay attack

#To modify the target to a specific equal-length value, encoded_target can be used
tampered_ciphertext = bytes.fromhex(ciphertext.hex()[:22] + b"HACK".hex() + ciphertext.hex()[30:])

print("REPLAY:\nCiphertext (hex) with target inserted: {}".format(tampered_ciphertext.hex()))

#Decrypt to show tampered plaintext
decryptor = cipher.decryptor()
recovered = (decryptor.update(tampered_ciphertext) + decryptor.finalize()).decode("unicode_escape")
print("Recovered (tampered) plaintext: {}".format(recovered))
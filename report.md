# CSCE-765 HW2, Preston Bodak 631002625

# Lab Prep

![alt text](images/labprep.png)

# Task 1

In order to modify a specific part of the decrypted plaintext, my design inserts
a series of bytes which match the length of the target into the ciphertext at
the same location as the target. To achieve this, it first converts the original
ciphertext into hex for ease of modification, since one byte can clearly be seen
as 2 hex characters. Since we know the plaintext and that each byte in the
plaintext maps directly to each byte in the ciphertext (due to the properties of
the XOR operation), we can see that READ belongs to bytes 11 through 14 in the
plaintext. This enables us to modify hex characters 22 through 29 in the ciphertext to produce a tampered output in the recovered plaintext. The screenshot below shows this in action.

![alt text](images/task1.png)

Above, you can see that where READ was originally found in the plaintext
has been modified after decryption to show another random sequence of
four characters. The root cause of this vulnerability is that the use of XOR
in counter mode for AES does not produce sufficient diffusion of the output.
The nature of the block cipher allows us to predict where certain parts of the
plaintext will appear in the ciphertext and make unauthorized modifications before
it is decrypted. For example, this may apply to a man-in-the-middle attack, where someone even without the key to decypt the message can still be familiar with the packet/frame structure and disrupt the contents of the message.

As a bonus, the source code also contains a snippet which demonstrates the ability to recover the key by first modifying the ciphertext to contain zeroes at the location of the target. After decryption of this ciphertext, the XOR operation simply inserts the key into the target location. This key can then be XOR-ed with a target message and re-inserted into the ciphertext to produce a negating XOR effect which directly shows the desired target message upon decryption.
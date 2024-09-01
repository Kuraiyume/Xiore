# Xiore Cipher
The Xiore Cipher is a proprietary symmetric encryption algorithm designed for robust data security. It operates with a 256-bit key and employs multiple rounds of encryption to secure plaintext data. This algorithm features custom-designed encryption and decryption routines, which include key expansion, S-Box substitutions, and bitwise rotations.

## Xiore Cipher is extremely challenging to decode without the correct key due to the following reasons:

- **Multiple Rounds**: The use of multiple encryption rounds ensures that the message is thoroughly scrambled. Each round applies key-dependent transformations, making the ciphertext increasingly difficult to decipher without the correct key.
- **Key-Dependent Operations**: The encryption process relies on key-dependent XOR operations, rotations, and S-Box substitutions. These operations are non-trivial to reverse, especially when compounded over multiple rounds.

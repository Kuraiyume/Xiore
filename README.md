# Xiore Cipher
The Xiore Cipher is a proprietary symmetric encryption algorithm designed for robust data security. It operates with a 256-bit key and employs multiple rounds of encryption to secure plaintext data. This algorithm features custom-designed encryption and decryption routines, which include key expansion, S-Box substitutions, and bitwise rotations.

## Xiore Cipher is extremely challenging to decode without the correct key due to the following reasons:

- **Rotation Operations**: The use of bitwise rotations (both left and right) introduces diffusion. This means that a change in one part of the plaintext will affect many parts of the ciphertext, making patterns harder to discern.
- **Substitution (S-box)**: Xiore use an S-box for byte substitution, which introduces non-linearity into the cipher. This non-linearity is crucial because it makes the relationship between plaintext and ciphertext more complex and less predictable.
- **Key Mixing**: By XORing with subkeys and rotating them, Xiore ensures that the key’s influence is spread throughout the encryption process. This helps prevent simple key recovery attacks.
- **256-bit Key**: A 256-bit key provides a vast key space, making brute-force attacks infeasible. The sheer number of possible keys (2^256) is astronomically large, making exhaustive search attacks impractical with current technology.
- **Multiple Rounds**: The use of multiple rounds (10) enhances security by applying the encryption transformations several times. Each round compounds the complexity, making it harder for an attacker to reverse-engineer the process or find patterns.
- **Custom Key Expansion**: Xiore's key expansion algorithm generates subkeys using XOR and bitwise rotations. While this method is non-standard, it can add complexity to the key schedule, making it harder to predict subkeys and increasing resistance to attacks like key recovery.

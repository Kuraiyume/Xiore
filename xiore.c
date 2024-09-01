/*
 * Xiore Cipher
 * Author: Z33phyr
 *
 * The Xiore Cipher is a proprietary symmetric encryption algorithm designed for robust data security. 
 * It operates with a 256-bit key and employs multiple rounds of encryption to secure plaintext data.
 *
 * This is a custom-designed algorithm! Users should be aware that it may not have undergone the extensive review and scrutiny that established standards have.
 * Some generated ciphers might be faulty. Double-check all operations to ensure accuracy (I'm still figuring out how to resolve this).
 * 
 * WARNING: THE AUTHOR ACCEPTS NO RESPONSIBILITY FOR ANY MISUSE OR POTENTIAL DATA LOSS. AS STATED, THIS IS A CUSTOM-DESIGNED ALGORITHM, AND THERE IS NO GUARANTEE REGARDING ITS SECURITY.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <openssl/rand.h>

#define ROTATE_RIGHT(val, shift, size) (((val) >> (shift)) | ((val) << ((size) - (shift))))
#define ROTATE_LEFT(val, shift, size) (((val) << (shift)) | ((val) >> ((size) - (shift))))

// Function prototypes
void obscureKeyGen(uint8_t *key);
void obscureKeyExpansion(const uint8_t *key, uint32_t *subKeys, int count);
void obscureEncryptRounds(char *msg, const uint8_t *key, int rounds, char *encMsg);
void obscureDecryptRounds(char *msg, const uint8_t *key, int rounds);
void obscureEncrypt(char *msg, uint32_t subKey, int round);
void obscureDecrypt(char *msg, uint32_t subKey, int round);
void obscureRotateRight(char *str, int length, int shift);
void obscureRotateLeft(char *str, int length, int shift);
void obscureToHex(const char *input, char *output, int length);
void obscureFromHex(const char *input, char *output, int length);
unsigned char obscureSBoxSub(unsigned char byte, unsigned char sBox[256]);
unsigned char obscureInvSBoxSub(unsigned char byte, unsigned char invSBox[256]);
void initSBox(unsigned char sBox[256], unsigned char invSBox[256]);

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "[*] Usage: %s --encrypt|--decrypt --message <message> [--key <key>]\n", argv[0]);
        return 1;
    }
    int encrypt = 0, decrypt = 0;
    char *message = NULL;
    char *key_str = NULL;
    uint8_t key[32];
    // Parse command-line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--encrypt") == 0) {
            encrypt = 1;
        } else if (strcmp(argv[i], "--decrypt") == 0) {
            decrypt = 1;
        } else if (strcmp(argv[i], "--message") == 0) {
            if (i + 1 < argc) {
                message = argv[++i];
            } else {
                fprintf(stderr, "[-] --message requires a value\n");
                return 1;
            }
        } else if (strcmp(argv[i], "--key") == 0) {
            if (i + 1 < argc) {
                key_str = argv[++i];
                obscureFromHex(key_str, (char *)key, 32);
            } else {
                fprintf(stderr, "[-] --key requires a value\n");
                return 1;
            }
        }
    }
    if (encrypt == decrypt || (!encrypt && !decrypt)) {
        fprintf(stderr, "[-] You must specify either --encrypt or --decrypt\n");
        return 1;
    }
    if (encrypt) {
        if (message == NULL) {
            fprintf(stderr, "[-] You must specify a message to encrypt using --message\n");
            return 1;
        } else if (key_str) {
            fprintf(stderr, "[-] Specifying the key when using --encrypt is not applicable\n");
            return 1;
        }
        obscureKeyGen(key); // Generate a random key for encryption
        char encrypted[200];
        obscureEncryptRounds(message, key, 10, encrypted);
        printf("[+] Encrypted message: %s\n", encrypted);
        char hexKey[65]; // Output the generated key in hexadecimal format
        obscureToHex((char *)key, hexKey, 32);
        printf("[+] Generated key: %s\n", hexKey);
    } else if (decrypt) {
        if (message == NULL || key_str == NULL) {
            fprintf(stderr, "[-] You must specify both the encrypted message and the 256-bit key using --message and --key\n");
            return 1;
        }
        char decrypted[100]; // Convert the hex-encoded message back to binary
        char hex_message[200];
        obscureFromHex(message, hex_message, strlen(message) / 2);
        obscureDecryptRounds(hex_message, key, 10);
        printf("[+] Decrypted message: %s\n", hex_message);
    }
    return 0;
}

// Generates a 256-bit (32-byte) random key using OpenSSL's RAND_bytes
void obscureKeyGen(uint8_t *key) {
    if (RAND_bytes(key, 32) != 1) {
        fprintf(stderr, "Error generating secure key\n");
        exit(1);
    }
}

// Expands the initial key into a series of subkeys for each encryption round
// The subkeys are derived from the original key and are rotated and XORed with constants
void obscureKeyExpansion(const uint8_t *key, uint32_t *subKeys, int count) {
    for (int i = 0; i < count; i++) {
        // Retrieve a 32-bit block from the key based on the current round index
        uint32_t tempKey = *(uint32_t *)(key + (i % 8) * 4);
        // Generate a subkey by XORing the key block with a round-specific constant and perform a left rotation
        subKeys[i] = tempKey ^ (0x5A827999 + (i * 0x6ED9EBA1));
        subKeys[i] = ROTATE_LEFT(subKeys[i], i % 32, 32);
        // Further mix the subkey by XORing it with a rotated version of the original key block
        subKeys[i] ^= ROTATE_RIGHT(tempKey, (i * 7) % 32, 32);
    }
}

// Encrypts the message through a series of rounds using the expanded subkeys
// The final encrypted message is converted to a hexadecimal string for display
void obscureEncryptRounds(char *msg, const uint8_t *key, int rounds, char *encMsg) {
    uint32_t subKeys[rounds]; // Array to hold the subkeys for each round
    obscureKeyExpansion(key, subKeys, rounds); // Generate subkeys from the original key
    // Encrypt the message through each round using the corresponding subkey
    for (int i = 0; i < rounds; i++) {
        obscureEncrypt(msg, subKeys[i], i);
    }
    // Convert the final encrypted message to a hexadecimal string
    obscureToHex(msg, encMsg, strlen(msg));
}

// Decrypts the message by reversing the encryption rounds
// The original message is obtained after applying all the decryption rounds
void obscureDecryptRounds(char *msg, const uint8_t *key, int rounds) {
    uint32_t subKeys[rounds]; // Array to hold the subkeys for each round
    obscureKeyExpansion(key, subKeys, rounds); // Generate subkeys from the original key
    // Decrypt the message through each round, starting from the last round to the first
    for (int i = rounds - 1; i >= 0; i--) {
        obscureDecrypt(msg, subKeys[i], i);
    }
}

// Encrypts a message using a single round of encryption with the given subkey and round index
void obscureEncrypt(char *msg, uint32_t subKey, int round) {
    int len = strlen(msg);
    int shift = (subKey ^ round) % len;
    unsigned char sBox[256], invSBox[256];
    initSBox(sBox, invSBox);
    // Apply transformations to each byte of the message
    for (int i = 0; i < len; i++) {
        msg[i] = (msg[i] + (subKey >> (i % 32))) % 256; // Add subKey component
        msg[i] ^= ROTATE_LEFT(subKey, i % 32, 32); // XOR with rotated subKey
    }
    obscureRotateRight(msg, len, shift); // Rotate right by shift amount
    for (int i = 0; i < len; i++) {
        msg[i] = obscureSBoxSub(msg[i], sBox); // Substitute using S-Box
    }
    for (int i = 0; i < len; i++) {
        msg[i] = (msg[i] ^ (subKey >> (i % 32))) ^ (ROTATE_RIGHT(subKey, round % 32, 32)); // Additional XORs
    }
    obscureRotateLeft(msg, len, (shift + round) % len); // Rotate left by modified shift amount
}

// Decrypts a message using a single round of decryption with the given subkey and round index
void obscureDecrypt(char *msg, uint32_t subKey, int round) {
    int len = strlen(msg);
    int shift = (subKey ^ round) % len;
    unsigned char sBox[256], invSBox[256];
    initSBox(sBox, invSBox);
    obscureRotateRight(msg, len, (shift + round) % len); // Rotate right by modified shift amount
    for (int i = 0; i < len; i++) {
        msg[i] = (msg[i] ^ (subKey >> (i % 32))) ^ (ROTATE_RIGHT(subKey, round % 32, 32)); // Reverse XORs
    }
    for (int i = 0; i < len; i++) {
        msg[i] = obscureInvSBoxSub(msg[i], invSBox); // Substitute using inverse S-Box
    }
    obscureRotateLeft(msg, len, shift); // Rotate left by shift amount
    for (int i = 0; i < len; i++) {
        msg[i] ^= ROTATE_LEFT(subKey, i % 32, 32); // XOR with rotated subKey
        msg[i] = (msg[i] - (subKey >> (i % 32))) % 256; // Subtract subKey component
    }
}

// Rotates a string to the right by a specified amount
void obscureRotateRight(char *str, int length, int shift) {
    char temp[length]; // Temporary buffer to hold the rotated string
    for (int i = 0; i < length; i++) {
        // Calculate the new position for each character and store it in the temporary buffer
        temp[(i + shift) % length] = str[i];
    }
    memcpy(str, temp, length); // Copy the rotated string back to the original buffer
}

// Rotates a string to the left by a specified amount
void obscureRotateLeft(char *str, int length, int shift) {
    char temp[length]; // Temporary buffer to hold the rotated string
    for (int i = 0; i < length; i++) {
        // Calculate the new position for each character and store it in the temporary buffer
        temp[i] = str[(i + shift) % length];
    }
    memcpy(str, temp, length); // Copy the rotated string back to the original buffer
}

// The substituted byte as defined by the S-Box. The value at index `byte` in the S-Box table is returned as the result of the substitution
unsigned char obscureSBoxSub(unsigned char byte, unsigned char sBox[256]) {
    return sBox[byte];
}

// Applies the inverse S-Box substitution to a single byte
unsigned char obscureInvSBoxSub(unsigned char byte, unsigned char invSBox[256]) {
    return invSBox[byte];
}

// Initializes the S-Box and its inverse S-Box for the cipher
// The inverse S-Box is used for decryption to reverse the substitution performed during encryption
// The S-Box is a fixed 256-byte array where each byte represents a substitution value
void initSBox(unsigned char sBox[256], unsigned char invSBox[256]) {
    static const unsigned char tempSBox[256] = {
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    };
    // Initialize the S-Box (sBox) and its inverse S-Box (invSBox)
    // The S-Box maps each possible byte value (0x00 to 0xFF) to a different byte value according to the fixed S-Box array
    // The inverse S-Box is used for decryption; it maps each byte value back to its original value before substitution
    for (int i = 0; i < 256; i++) {
         // Set the value of the S-Box at index 'i' to the corresponding value from the predefined S-Box array
        sBox[i] = tempSBox[i];
        // Set the inverse S-Box at index 'tempSBox[i]' to the index 'i'
        // This operation ensures that if 'tempSBox[i]' maps to 'i', then 'invSBox[tempSBox[i]]' maps back to 'i'
        invSBox[tempSBox[i]] = i;
    }
}

// Converts a binary string to its hexadecimal representation
void obscureToHex(const char *input, char *output, int length) {
    for (int i = 0; i < length; i++) {
        sprintf(output + i * 2, "%02X", (unsigned char)input[i]);
    }
}

// Converts a hexadecimal string to its binary representation
void obscureFromHex(const char *input, char *output, int length) {
    for (int i = 0; i < length; i++) {
        sscanf(input + i * 2, "%2hhx", &output[i]);
    }
}


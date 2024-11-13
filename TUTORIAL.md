# Boundless Blockchain: Step-by-Step Tutorial

This tutorial walks you through building a basic Proof-of-Work blockchain in C, covering essential concepts like hashing, block structure, linking blocks, Proof-of-Work, and validation. 

## Step 1: Implementing Hash Functions

Bitcoin relies heavily on cryptographic hashing, specifically SHA-256, which takes any input and returns a fixed-length, 256-bit (32-byte) output. ...

### Objective
Implement or include a SHA-256 function in C and verify its correctness.

### Implementation
Here’s a sample wrapper function to calculate SHA-256 hashes in C using OpenSSL:

```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/sha.h>

void calc_sha_256(uint8_t hash[SHA256_DIGEST_LENGTH], const char *string) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, strlen(string));
    SHA256_Final(hash, &sha256);
}

void print_hash(uint8_t hash[SHA256_DIGEST_LENGTH]) {
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

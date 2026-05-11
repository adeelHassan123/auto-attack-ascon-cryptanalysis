/**
 * @file ascon_wrapper.c
 * @brief Simple wrapper for ASCON-128 encryption suitable for side-channel analysis.
 * 
 * This wrapper provides a clean interface for the Rainbow emulator to call
 * ASCON-128 encryption with raw byte arrays.
 */

#include <stdint.h>
#include <string.h>
#include "../inc/ascon_aead128.h"

/* ASCON S-box lookup table */
static const uint8_t SBOX[32] = {
    0x04, 0x0b, 0x1f, 0x14, 0x1a, 0x15, 0x09, 0x02,
    0x1b, 0x05, 0x08, 0x12, 0x1d, 0x03, 0x06, 0x1c,
    0x1e, 0x13, 0x07, 0x0e, 0x00, 0x0d, 0x11, 0x18,
    0x10, 0x0c, 0x01, 0x19, 0x16, 0x0a, 0x0f, 0x17
};

/* Round constants */
static const uint8_t RC[16] = {
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
    0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f
};

static uint64_t rotr(uint64_t x, int n) {
    return (x >> n) | (x << (64 - n));
}

void init_state(State *s, const uint8_t *key, const uint8_t *nonce) {
    s->s0 = ASCON_IV;
    s->s1 = ((uint64_t)key[0] << 56) | ((uint64_t)key[1] << 48) |
            ((uint64_t)key[2] << 40) | ((uint64_t)key[3] << 32) |
            ((uint64_t)key[4] << 24) | ((uint64_t)key[5] << 16) |
            ((uint64_t)key[6] << 8)  | (uint64_t)key[7];
    s->s2 = ((uint64_t)key[8] << 56) | ((uint64_t)key[9] << 48) |
            ((uint64_t)key[10] << 40) | ((uint64_t)key[11] << 32) |
            ((uint64_t)key[12] << 24) | ((uint64_t)key[13] << 16) |
            ((uint64_t)key[14] << 8) | (uint64_t)key[15];
    s->s3 = ((uint64_t)nonce[0] << 56) | ((uint64_t)nonce[1] << 48) |
            ((uint64_t)nonce[2] << 40) | ((uint64_t)nonce[3] << 32) |
            ((uint64_t)nonce[4] << 24) | ((uint64_t)nonce[5] << 16) |
            ((uint64_t)nonce[6] << 8) | (uint64_t)nonce[7];
    s->s4 = ((uint64_t)nonce[8] << 56) | ((uint64_t)nonce[9] << 48) |
            ((uint64_t)nonce[10] << 40) | ((uint64_t)nonce[11] << 32) |
            ((uint64_t)nonce[12] << 24) | ((uint64_t)nonce[13] << 16) |
            ((uint64_t)nonce[14] << 8) | (uint64_t)nonce[15];
}

uint64_t rotate_right(uint64_t x, int n) {
    return rotr(x, n);
}

void pc(State *s, int round) {
    s->s2 ^= RC[round];
}

void ps(State *s) {
    int i;
    uint64_t new_s[5] = {0};
    
    for (i = 0; i < 64; i++) {
        int col = 0;
        /* Correct ASCON bit order: s0 is MSB (bit 4), s4 is LSB (bit 0) */
        col |= ((s->s0 >> i) & 1) << 4;
        col |= ((s->s1 >> i) & 1) << 3;
        col |= ((s->s2 >> i) & 1) << 2;
        col |= ((s->s3 >> i) & 1) << 1;
        col |= ((s->s4 >> i) & 1) << 0;
        
        int new_col = SBOX[col];
        
        new_s[0] |= (uint64_t)((new_col >> 4) & 1) << i;
        new_s[1] |= (uint64_t)((new_col >> 3) & 1) << i;
        new_s[2] |= (uint64_t)((new_col >> 2) & 1) << i;
        new_s[3] |= (uint64_t)((new_col >> 1) & 1) << i;
        new_s[4] |= (uint64_t)((new_col >> 0) & 1) << i;
    }
    
    s->s0 = new_s[0];
    s->s1 = new_s[1];
    s->s2 = new_s[2];
    s->s3 = new_s[3];
    s->s4 = new_s[4];
}

void pl(State *s) {
    uint64_t t0, t1, t2, t3, t4;
    t0 = s->s0;
    t1 = s->s1;
    t2 = s->s2;
    t3 = s->s3;
    t4 = s->s4;
    
    s->s0 = t0 ^ rotr(t0, 19) ^ rotr(t0, 28);
    s->s1 = t1 ^ rotr(t1, 61) ^ rotr(t1, 39);
    s->s2 = t2 ^ rotr(t2, 1)  ^ rotr(t2, 6);
    s->s3 = t3 ^ rotr(t3, 10) ^ rotr(t3, 17);
    s->s4 = t4 ^ rotr(t4, 7)  ^ rotr(t4, 41);
}

void permutation(State *s, int rounds, int start_round) {
    int i;
    for (i = 0; i < rounds; i++) {
        pc(s, start_round + i);
        ps(s);
        pl(s);
    }
}

void p6(State *s) {
    permutation(s, 6, 6);
}

void p12(State *s) {
    permutation(s, 12, 0);
}

uint8_t get_column_value(State *s, int column) {
    uint8_t col = 0;
    col |= ((s->s0 >> column) & 1) << 4;
    col |= ((s->s1 >> column) & 1) << 3;
    col |= ((s->s2 >> column) & 1) << 2;
    col |= ((s->s3 >> column) & 1) << 1;
    col |= ((s->s4 >> column) & 1) << 0;
    return col;
}

void change_column_value(State *s, int column, uint8_t value) {
    uint64_t mask = ~(1ULL << column);
    s->s0 = (s->s0 & mask) | (((uint64_t)(value >> 4) & 1) << column);
    s->s1 = (s->s1 & mask) | (((uint64_t)(value >> 3) & 1) << column);
    s->s2 = (s->s2 & mask) | (((uint64_t)(value >> 2) & 1) << column);
    s->s3 = (s->s3 & mask) | (((uint64_t)(value >> 1) & 1) << column);
    s->s4 = (s->s4 & mask) | (((uint64_t)(value >> 0) & 1) << column);
}

/**
 * @brief Simple ASCON-128 encryption wrapper for Rainbow.
 * 
 * Function signature: void ascon_encrypt_simple(key, nonce, pt, ct, tag)
 * 
 * This implementation follows the standard ASCON-128 AEAD flow for
 * a single 16-byte block with no associated data.
 * 
 * @param key     16-byte key
 * @param nonce   16-byte nonce
 * @param pt      16-byte plaintext
 * @param ct      16-byte ciphertext output
 * @param tag     16-byte tag output
 */
void ascon_encrypt_simple(const uint8_t *key, const uint8_t *nonce,
                          const uint8_t *plaintext, uint8_t *ciphertext,
                          uint8_t *tag) {
    State s;
    uint64_t k0, k1, n0, n1;
    
    k0 = ((uint64_t)key[0] << 56) | ((uint64_t)key[1] << 48) |
         ((uint64_t)key[2] << 40) | ((uint64_t)key[3] << 32) |
         ((uint64_t)key[4] << 24) | ((uint64_t)key[5] << 16) |
         ((uint64_t)key[6] << 8)  | (uint64_t)key[7];
    k1 = ((uint64_t)key[8] << 56) | ((uint64_t)key[9] << 48) |
         ((uint64_t)key[10] << 40) | ((uint64_t)key[11] << 32) |
         ((uint64_t)key[12] << 24) | ((uint64_t)key[13] << 16) |
         ((uint64_t)key[14] << 8) | (uint64_t)key[15];
    n0 = ((uint64_t)nonce[0] << 56) | ((uint64_t)nonce[1] << 48) |
         ((uint64_t)nonce[2] << 40) | ((uint64_t)nonce[3] << 32) |
         ((uint64_t)nonce[4] << 24) | ((uint64_t)nonce[5] << 16) |
         ((uint64_t)nonce[6] << 8)  | (uint64_t)nonce[7];
    n1 = ((uint64_t)nonce[8] << 56) | ((uint64_t)nonce[9] << 48) |
         ((uint64_t)nonce[10] << 40) | ((uint64_t)nonce[11] << 32) |
         ((uint64_t)nonce[12] << 24) | ((uint64_t)nonce[13] << 16) |
         ((uint64_t)nonce[14] << 8) | (uint64_t)nonce[15];

    /* Initialization */
    s.s0 = ASCON_IV;
    s.s1 = k0;
    s.s2 = k1;
    s.s3 = n0;
    s.s4 = n1;
    p12(&s);
    s.s3 ^= k0;
    s.s4 ^= k1;

    /* Domain separation (no AD) */
    s.s4 ^= 1;
    
    /* Process first 8 bytes of PT */
    uint64_t m0 = ((uint64_t)plaintext[0] << 56) | ((uint64_t)plaintext[1] << 48) |
                  ((uint64_t)plaintext[2] << 40) | ((uint64_t)plaintext[3] << 32) |
                  ((uint64_t)plaintext[4] << 24) | ((uint64_t)plaintext[5] << 16) |
                  ((uint64_t)plaintext[6] << 8)  | (uint64_t)plaintext[7];
    s.s0 ^= m0;
    ciphertext[0] = (s.s0 >> 56) & 0xff; ciphertext[1] = (s.s0 >> 48) & 0xff;
    ciphertext[2] = (s.s0 >> 40) & 0xff; ciphertext[3] = (s.s0 >> 32) & 0xff;
    ciphertext[4] = (s.s0 >> 24) & 0xff; ciphertext[5] = (s.s0 >> 16) & 0xff;
    ciphertext[6] = (s.s0 >> 8) & 0xff;  ciphertext[7] = s.s0 & 0xff;
    p6(&s);

    /* Process next 8 bytes of PT */
    uint64_t m1 = ((uint64_t)plaintext[8] << 56) | ((uint64_t)plaintext[9] << 48) |
                  ((uint64_t)plaintext[10] << 40) | ((uint64_t)plaintext[11] << 32) |
                  ((uint64_t)plaintext[12] << 24) | ((uint64_t)plaintext[13] << 16) |
                  ((uint64_t)plaintext[14] << 8) | (uint64_t)plaintext[15];
    s.s0 ^= m1;
    ciphertext[8] = (s.s0 >> 56) & 0xff;  ciphertext[9] = (s.s0 >> 48) & 0xff;
    ciphertext[10] = (s.s0 >> 40) & 0xff; ciphertext[11] = (s.s0 >> 32) & 0xff;
    ciphertext[12] = (s.s0 >> 24) & 0xff; ciphertext[13] = (s.s0 >> 16) & 0xff;
    ciphertext[14] = (s.s0 >> 8) & 0xff;  ciphertext[15] = s.s0 & 0xff;
    p6(&s);

    /* Padding for finalization */
    s.s0 ^= 0x8000000000000000ULL;

    /* Finalization */
    s.s1 ^= k0;
    s.s2 ^= k1;
    p12(&s);
    s.s3 ^= k0;
    s.s4 ^= k1;
    
    /* Output tag (s3 || s4) */
    tag[0] = (s.s3 >> 56) & 0xff; tag[1] = (s.s3 >> 48) & 0xff;
    tag[2] = (s.s3 >> 40) & 0xff; tag[3] = (s.s3 >> 32) & 0xff;
    tag[4] = (s.s3 >> 24) & 0xff; tag[5] = (s.s3 >> 16) & 0xff;
    tag[6] = (s.s3 >> 8) & 0xff;  tag[7] = s.s3 & 0xff;
    tag[8] = (s.s4 >> 56) & 0xff; tag[9] = (s.s4 >> 48) & 0xff;
    tag[10] = (s.s4 >> 40) & 0xff; tag[11] = (s.s4 >> 32) & 0xff;
    tag[12] = (s.s4 >> 24) & 0xff; tag[13] = (s.s4 >> 16) & 0xff;
    tag[14] = (s.s4 >> 8) & 0xff;  tag[15] = s.s4 & 0xff;
}

#ifdef ASCON_TEST_MAIN
#include <stdio.h>

int main(void) {
    uint8_t key[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    uint8_t nonce[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    uint8_t pt[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    uint8_t ct[16], tag[16];
    
    uint8_t pt16_tag[16] = {
        0xf5, 0x8e, 0x28, 0x43, 0x6d, 0xd7, 0x15, 0x56,
        0xd5, 0x8d, 0xfa, 0x56, 0xac, 0x89, 0x0b, 0xeb
    };
    
    printf("ASCON-128 Wrapper Verification\n");
    printf("==============================\n");
    
    printf("Test: PT=16, AD=0\n");
    ascon_encrypt_simple(key, nonce, pt, ct, tag);
    
    printf("Tag:    ");
    for (int i = 0; i < 16; i++) printf("%02x", tag[i]);
    printf("\n");
    printf("Expect: ");
    for (int i = 0; i < 16; i++) printf("%02x", pt16_tag[i]);
    printf("\n");
    
    if (memcmp(tag, pt16_tag, 16) == 0) {
        printf("[PASS]\n");
        return 0;
    } else {
        printf("[FAIL]\n");
        return 1;
    }
}
#endif

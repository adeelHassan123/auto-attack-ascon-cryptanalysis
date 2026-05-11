#ifndef ASCON_AEAD128_H
#define ASCON_AEAD128_H

#include <stdint.h>
#include <stdlib.h>

/* ASCON-128 state (5 x 64-bit words) */
typedef struct {
    uint64_t s0;
    uint64_t s1;
    uint64_t s2;
    uint64_t s3;
    uint64_t s4;
} State;

/* ASCON-128 IV */
#define ASCON_IV 0x80400c0600000000ULL

/* Function prototypes */
void init_state(State *s, const uint8_t *key, const uint8_t *nonce);
void pc(State *s, int round);
void ps(State *s);
void pl(State *s);
void p6(State *s);
void p12(State *s);
uint64_t rotate_right(uint64_t x, int n);

/* Simple encryption function for Rainbow */
void ascon_encrypt_simple(const uint8_t *key, const uint8_t *nonce, 
                          const uint8_t *plaintext, uint8_t *ciphertext, 
                          uint8_t *tag);

/* Get a specific column value (0-63) from the state */
uint8_t get_column_value(State *s, int column);

/* Change a specific column value */
void change_column_value(State *s, int column, uint8_t value);

#endif /* ASCON_AEAD128_H */

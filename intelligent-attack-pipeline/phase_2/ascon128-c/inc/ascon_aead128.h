#ifndef ASCON_AEAD128_H
#define ASCON_AEAD128_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/* Maximum index for a 64-bit word */
#define MAX_WORD_INDEX UINT8_C(63)

#define DECRYPTION_VALID     UINT8_C(1)
#define DECRYPTION_NOT_VALID UINT8_C(0)

/* First round of p6() operation - ASCON-128 uses pb=6 rounds */
#define P6_FIRST_RND  UINT8_C(10)
/* First round of p12() operation - ASCON-128 uses pa=12 rounds */
#define P12_FIRST_RND UINT8_C(4)
/* Maximum round of a p() operation */
#define P_MAX_RND     UINT8_C(15)

extern const uint8_t ROUND_CONSTANT[16];

extern const uint8_t SUBSTITUTION_CONSTANT[32];

extern const uint64_t IV;

typedef struct {
    uint64_t msb;
    uint64_t lsb;
} uint128_t;

typedef uint128_t Key;
typedef uint128_t Nonce;
typedef uint128_t Tag;

typedef struct {
    uint64_t s0;
    uint64_t s1;
    uint64_t s2;
    uint64_t s3;
    uint64_t s4;
} State;

typedef struct {
    uint128_t *arr;
    uint64_t size;
} Data;

typedef Data AssociatedData;
typedef Data Ciphertext;
typedef Data Plaintext;

typedef struct {
    Ciphertext ciphertext;
    Tag tag;
} EncryptionResult;

typedef struct {
    Plaintext plaintext;
    uint8_t valid;
} DecryptionResult;

void init_state(State *state, Key *key, Nonce *nonce);
uint8_t init_enc_result(EncryptionResult **result, uint64_t size);
uint8_t init_dec_result(DecryptionResult **result, uint64_t size);
void free_encryption_result(EncryptionResult *result);
void free_decryption_result(DecryptionResult *result);
void pc(State *state, uint8_t rnd);
void ps(State *state);
void pl(State *state);
void permutation(State *state, uint8_t rnd);
void p6(State *state);
void p12(State *state);
EncryptionResult *ascon128_enc(Key *key, Nonce *nonce, AssociatedData *associated_data, Plaintext *plaintext);
DecryptionResult *ascon128_dec(Key *key, Nonce *nonce, AssociatedData *associated_data, EncryptionResult *enc);

static inline uint8_t get_column_value(State *state, uint8_t index) {
    uint64_t shift = (uint64_t)(MAX_WORD_INDEX - index);
    return (uint8_t)((((state->s0 >> shift) & UINT64_C(1)) << UINT64_C(4))
                  +  (((state->s1 >> shift) & UINT64_C(1)) << UINT64_C(3))
                  +  (((state->s2 >> shift) & UINT64_C(1)) << UINT64_C(2))
                  +  (((state->s3 >> shift) & UINT64_C(1)) << UINT64_C(1))
                  +   ((state->s4 >> shift) & UINT64_C(1)));
}

static inline void change_column_value(State *state, uint8_t index, uint8_t new_val) {
    uint64_t shift = (uint64_t)(MAX_WORD_INDEX - index);
    // bit at index is clear for each sub-state
    state->s0 &= ~(UINT64_C(1) << shift);
    state->s1 &= ~(UINT64_C(1) << shift);
    state->s2 &= ~(UINT64_C(1) << shift);
    state->s3 &= ~(UINT64_C(1) << shift);
    state->s4 &= ~(UINT64_C(1) << shift);
    // put new bit value for each sub-state
    state->s0 |= (uint64_t)((new_val >> UINT8_C(4)) & UINT8_C(1)) << shift;
    state->s1 |= (uint64_t)((new_val >> UINT8_C(3)) & UINT8_C(1)) << shift;
    state->s2 |= (uint64_t)((new_val >> UINT8_C(2)) & UINT8_C(1)) << shift;
    state->s3 |= (uint64_t)((new_val >> UINT8_C(1)) & UINT8_C(1)) << shift;
    state->s4 |= (uint64_t)( new_val                & UINT8_C(1)) << shift;
}

static inline uint64_t rotate_right(uint64_t val, uint8_t index) {
    return (val >> (uint64_t)index) | (val << (uint64_t)(UINT8_C(64) - index));
}

#ifdef __cplusplus
}
#endif

#endif 
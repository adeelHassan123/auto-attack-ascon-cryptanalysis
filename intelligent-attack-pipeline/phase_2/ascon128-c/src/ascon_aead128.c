#include <stdlib.h>
#include "../inc/ascon_aead128.h"

// Minimal heap implementation for embedded systems
#define HEAP_SIZE 4096
static uint8_t heap[HEAP_SIZE];
static uint32_t heap_used = 0;

static void *embedded_memset(void *s, int c, size_t n);
static void *embedded_memset(void *s, int c, size_t n) {
    volatile uint8_t *ptr = (volatile uint8_t *)s;
    while (n-- > 0) {
        *ptr++ = (uint8_t)c;
    }
    return s;
}

static void *embedded_calloc(size_t nmemb, size_t size) {
    size_t total_size = nmemb * size;
    if (heap_used + total_size > HEAP_SIZE) {
        return NULL;
    }
    void *ptr = &heap[heap_used];
    heap_used += total_size;
    // Zero out the memory
    embedded_memset(ptr, 0, total_size);
    return ptr;
}

static void embedded_free(void *ptr) {
    // Simple no-op free for embedded - memory is not reclaimed
    (void)ptr;
}

const uint8_t ROUND_CONSTANT[16] = {
    0x3C, 0x2D, 0x1E, 0x0F, 0xF0, 0xE1, 0xD2, 0xC3,
    0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B,
};

const uint8_t SUBSTITUTION_CONSTANT[32] = {
    0x04, 0x0B, 0x1F, 0x14, 0x1A, 0x15, 0x09, 0x02,
    0x1B, 0x05, 0x08, 0x12, 0x1D, 0x03, 0x06, 0x1C,
    0x1E, 0x13, 0x07, 0x0E, 0x00, 0x0D, 0x11, 0x18,
    0x10, 0x0C, 0x01, 0x19, 0x16, 0x0A, 0x0F, 0x17,
};

/* ASCON-128 IV: pa=12, pb=6, rate=64 -> 0x80400c0600000000 */
const uint64_t IV = UINT64_C(0x80400c0600000000);

/**
 * @brief Initialize the Ascon state.
 * @param[out] state The Ascon state to be initialized.
 * @param[in]  key   The key used for the encryption/decryption.
 * @param[in]  nonce The nonce used.
 */
void init_state(State *state, Key *key, Nonce *nonce) {
    state->s0 = IV;
    state->s1 = key->msb;
    state->s2 = key->lsb;
    state->s3 = nonce->msb;
    state->s4 = nonce->lsb;
}

/**
 * @brief Initialize the result of a Ascon128 encryption.
 * @param[out] result Pointer to a pointer that will receive the allocated structure.
 * @param[in]  size   Number of elements in the ciphertext array.
 * @retval 0 Dynamic memory allocation suceeded.
 * @retval 1 Dynamic memory allocation failed.
 */
uint8_t init_enc_result(EncryptionResult **result, uint64_t size) {
    if (result == NULL) {
        return 1;
    }

    *result = embedded_calloc(1, sizeof(EncryptionResult));
    if (*result == NULL) {
        return 1;
    }

    (*result)->ciphertext.arr = embedded_calloc(size, sizeof(uint128_t));
    if ((*result)->ciphertext.arr == NULL) {
        embedded_free(*result);
        *result = NULL;
        return 1;
    }

    (*result)->ciphertext.size = size;

    return 0;
}

/**
 * @brief Initialize the result of a Ascon128 decryption.
 * @param[out] result Pointer to a pointer that will receive the allocated structure.
 * @param[in]  size   Number of elements in the plaintext array.
 * @retval 0 Dynamic memory allocation suceeded.
 * @retval 1 Dynamic memory allocation failed.
 */
uint8_t init_dec_result(DecryptionResult **result, uint64_t size) {
    if (result == NULL) {
        return 1;
    }

    *result = embedded_calloc(1, sizeof(DecryptionResult));
    if (*result == NULL) {
        return 1;
    }

    (*result)->plaintext.arr = embedded_calloc(size, sizeof(uint128_t));
    if ((*result)->plaintext.arr == NULL) {
        embedded_free(*result);
        *result = NULL;
        return 1;
    }

    (*result)->valid = DECRYPTION_NOT_VALID;
    (*result)->plaintext.size = size;

    return 0;
}

/**
 * @brief Free all memory owned by an EncryptionResult object.
 *
 * Releases the ciphertext array and the EncryptionResult structure itself.
 * Does not modify the caller's pointer; the caller should set it to NULL
 * after this function returns to avoid a dangling pointer.
 *
 * @param[in] result Pointer to an EncryptionResult allocated by
 *                   init_enc_result or similar allocation function.
 *                   May be NULL, in which case the function has no effect.
 */
void free_encryption_result(EncryptionResult *result) {
    uint64_t i; // for loop iterator
    if (result != NULL) {
        if (result->ciphertext.arr != NULL) {
            for (i = UINT64_C(0); i < result->ciphertext.size; i++) {
                // erase data
                result->ciphertext.arr[i] = (uint128_t){UINT64_C(0), UINT64_C(0)};
            }
            // free memory
            embedded_free(result->ciphertext.arr);
            // set pointer to NULL to avoid dangling pointer
            result->ciphertext.arr = NULL;
        }
        // erase data
        result->tag = (uint128_t){UINT64_C(0), UINT64_C(0)};
        // free memory
        embedded_free(result);
    }
}

/**
 * @brief Free all memory owned by a DecryptionResult object.
 *
 * Releases the plaintext array and the DecryptionResult structure itself.
 * Does not modify the caller's pointer; the caller should set it to NULL
 * after this function returns to avoid a dangling pointer.
 *
 * @param[in] result Pointer to a DecryptionResult allocated by
 *                   the corresponding allocation function.
 *                   May be NULL, in which case the function has no effect.
 */
void free_decryption_result(DecryptionResult *result) {
    uint64_t i; // for loop iterator
    if (result != NULL) {
        if (result->plaintext.arr != NULL) {
            for (i = UINT64_C(0); i < result->plaintext.size; i++) {
                // erase data
                result->plaintext.arr[i] = (uint128_t){UINT64_C(0), UINT64_C(0)};
            }
            // free memory
            embedded_free(result->plaintext.arr);
            // set pointer to NULL to avoid dangling pointer
            result->plaintext.arr = NULL;
        }
        // erase data
        result->valid = DECRYPTION_NOT_VALID;
        // free memory
        embedded_free(result);
    }
}

/**
 * @brief Add constant.
 * @param[in,out] state The current Ascon state.
 * @param[in]     round The current permutation round.
 * @note rnd value must be less than or equal to P_MAX_RND.
 */
void pc(State *state, uint8_t rnd) {
    state->s2 ^= (uint64_t)ROUND_CONSTANT[rnd];
}

/**
 * @brief State substitution.
 * @param[in,out] state The current Ascon state.
 */
void ps(State *state) {
    uint8_t col_index;
    uint8_t column_val;

    for (col_index = UINT8_C(0); col_index <= MAX_WORD_INDEX; col_index++) {
        column_val = get_column_value(state, col_index);
        change_column_value(state, col_index, SUBSTITUTION_CONSTANT[column_val]);
    }
}

/**
 * @brief State diffusion.
 * @param[in,out] state The current Ascon state.
 */
void pl(State *state) {
    state->s0 ^= rotate_right(state->s0, UINT8_C(19)) ^ rotate_right(state->s0, UINT8_C(28));
    state->s1 ^= rotate_right(state->s1, UINT8_C(61)) ^ rotate_right(state->s1, UINT8_C(39));
    state->s2 ^= rotate_right(state->s2, UINT8_C( 1)) ^ rotate_right(state->s2, UINT8_C( 6));
    state->s3 ^= rotate_right(state->s3, UINT8_C(10)) ^ rotate_right(state->s3, UINT8_C(17));
    state->s4 ^= rotate_right(state->s4, UINT8_C( 7)) ^ rotate_right(state->s4, UINT8_C(41));
}

/**
 * @brief State permutation.
 * @param[in,out] state The current Ascon state.
 * @param[in]     rnd   The current permutation round
 * @note round value must be less than or equal to 15.
 */
void permutation(State *state, uint8_t rnd) {
    pc(state, rnd);
    ps(state);
    pl(state);
}

/**
 * @brief Perform p6 operation (ASCON-128 data processing pb=6).
 * @param[in,out] state The current Ascon state.
 */
void p6(State *state) {
    uint8_t rnd;

    for (rnd = P6_FIRST_RND; rnd <= P_MAX_RND; rnd++) {
        permutation(state, rnd);
    }
}

/**
 * @brief Perform p12 operation.
 * @param[in,out] state The current Ascon state.
 */
void p12(State *state) {
    uint8_t rnd;

    for (rnd = P12_FIRST_RND; rnd <= P_MAX_RND; rnd++) {
        permutation(state, rnd);
    }
}

/**
 * @brief Perform Ascon128 encryption.
 * @param[in] key             The key.
 * @param[in] nonce           The nonce.
 * @param[in] associated_data The associated data.
 * @param[in] plaintext       The text to be ciphered.
 * @return The ciphertext and the tag.
 */
EncryptionResult *ascon128_enc(Key *key, Nonce *nonce, AssociatedData *associated_data, Plaintext *plaintext) {
    uint64_t i; // for loop iterator
    State s;
    EncryptionResult *result = NULL;

    if (init_enc_result(&result, plaintext->size) != UINT8_C(0)) {
        // abort encryption if memory allocation failed
        return NULL;
    }

    init_state(&s, key, nonce);
    p12(&s);
    s.s3 ^= key->msb;
    s.s4 ^= key->lsb;

    if (associated_data->size > UINT64_C(0)) {
        for (i = UINT64_C(0); i < associated_data->size; i++) {
            s.s0 ^= associated_data->arr[i].msb;
            s.s1 ^= associated_data->arr[i].lsb;
            p6(&s);
        }
    }
    s.s4 ^= UINT64_C(1);

    for (i = UINT64_C(0); i < (uint64_t)(plaintext->size - UINT64_C(1)); i++) {
        s.s0 ^= plaintext->arr[i].msb;
        s.s1 ^= plaintext->arr[i].lsb;
        result->ciphertext.arr[i].msb = s.s0;
        result->ciphertext.arr[i].lsb = s.s1;
        p6(&s);
    }
    s.s0 ^= plaintext->arr[plaintext->size-1].msb;
    s.s1 ^= plaintext->arr[plaintext->size-1].lsb;
    result->ciphertext.arr[plaintext->size-1].msb = s.s0;
    result->ciphertext.arr[plaintext->size-1].lsb = s.s1;

    s.s2 ^= key->msb;
    s.s3 ^= key->lsb;
    p12(&s);

    result->tag.msb = s.s3 ^ key->msb;
    result->tag.lsb = s.s4 ^ key->lsb;
    return result;
}

/**
 * @brief Perform Ascon128 decryption.
 * @param[in] key             The key.
 * @param[in] nonce           The nonce.
 * @param[in] associated_data The associated data.
 * @param[in] enc             The tag and cipher.
 * @return The plaintext and an indicator about its validity.
 * @note User should ensure memory deallocation for enc after call to this function
 */
DecryptionResult *ascon128_dec(Key *key, Nonce *nonce, AssociatedData *associated_data, EncryptionResult *enc) {
    uint64_t i; // for loop iterator
    State s;
    DecryptionResult *result = NULL;
    Tag tag;

    if (enc == NULL || init_dec_result(&result, enc->ciphertext.size) != UINT8_C(0)) {
        // abort decryption if memory allocation failed
        return NULL;
    }

    init_state(&s, key, nonce);
    p12(&s);
    s.s3 ^= key->msb;
    s.s4 ^= key->lsb;

    if (associated_data->size > UINT64_C(0)) {
        for (i = UINT64_C(0); i < associated_data->size; i++) {
            s.s0 ^= associated_data->arr[i].msb;
            s.s1 ^= associated_data->arr[i].lsb;
            p6(&s);
        }
    }
    s.s4 ^= UINT64_C(1);

    for (i = UINT64_C(0); i < (uint64_t)(enc->ciphertext.size - UINT64_C(1)); i++) {
        result->plaintext.arr[i].msb = s.s0 ^ enc->ciphertext.arr[i].msb;
        result->plaintext.arr[i].lsb = s.s1 ^ enc->ciphertext.arr[i].lsb;
        s.s0 = enc->ciphertext.arr[i].msb;
        s.s1 = enc->ciphertext.arr[i].lsb;
        p6(&s);
    }

    result->plaintext.arr[enc->ciphertext.size-1].msb = s.s0 ^ enc->ciphertext.arr[enc->ciphertext.size-1].msb;
    result->plaintext.arr[enc->ciphertext.size-1].lsb = s.s1 ^ enc->ciphertext.arr[enc->ciphertext.size-1].lsb;
    s.s0 = enc->ciphertext.arr[enc->ciphertext.size-1].msb;
    s.s1 = enc->ciphertext.arr[enc->ciphertext.size-1].lsb;
    s.s2 ^= key->msb;
    s.s3 ^= key->lsb;
    p12(&s);

    tag.msb = s.s3 ^ key->msb;
    tag.lsb = s.s4 ^ key->lsb;

    if (tag.msb == enc->tag.msb && tag.lsb == enc->tag.lsb) {
        result->valid = DECRYPTION_VALID;
    }

    return result;
}
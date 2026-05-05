/**
 * @file ascon_wrapper.c
 * @brief Simple wrapper for ASCON-128 encryption with raw byte interface.
 * 
 * This wrapper provides a function suitable for side-channel analysis
 * that takes raw byte arrays instead of complex structs.
 */

#include <stdint.h>
#include <string.h>
#include "../inc/ascon_aead128.h"

// Memory for single block encryption (avoids dynamic allocation)
static EncryptionResult result;
static uint128_t ct_block;
static uint128_t pt_block;

/**
 * @brief Simple ASCON-128 encryption wrapper for SCA.
 * 
 * Takes raw 16-byte arrays for key, nonce, and plaintext.
 * Produces 16-byte ciphertext and 16-byte tag.
 * 
 * @param[in]  key       16-byte key
 * @param[in]  nonce     16-byte nonce
 * @param[in]  plaintext 16-byte plaintext
 * @param[out] ciphertext 16-byte output buffer for ciphertext
 * @param[out] tag       16-byte output buffer for tag
 * @return 0 on success, non-zero on error
 */
int ascon_encrypt(const uint8_t *key, const uint8_t *nonce, 
                  const uint8_t *plaintext, uint8_t *ciphertext, 
                  uint8_t *tag) {
    Key k;
    Nonce n;
    Plaintext pt;
    AssociatedData ad;
    EncryptionResult *res;
    
    // Convert key bytes to struct
    memcpy(&k.msb, key, 8);
    memcpy(&k.lsb, key + 8, 8);
    
    // Convert nonce bytes to struct  
    memcpy(&n.msb, nonce, 8);
    memcpy(&n.lsb, nonce + 8, 8);
    
    // Setup plaintext (single 16-byte block)
    pt.size = 1;
    memcpy(&pt_block.msb, plaintext, 8);
    memcpy(&pt_block.lsb, plaintext + 8, 8);
    pt.arr = &pt_block;
    
    // Setup associated data (empty for simplicity)
    ad.size = 0;
    ad.arr = NULL;
    
    // Perform encryption
    res = ascon128_enc(&k, &n, &ad, &pt);
    if (res == NULL) {
        return -1;
    }
    
    // Copy results back
    if (res->ciphertext.size > 0) {
        memcpy(ciphertext, &res->ciphertext.arr[0].msb, 8);
        memcpy(ciphertext + 8, &res->ciphertext.arr[0].lsb, 8);
    }
    memcpy(tag, &res->tag.msb, 8);
    memcpy(tag + 8, &res->tag.lsb, 8);
    
    return 0;
}

/**
 * @brief Even simpler wrapper - single 16-byte block encryption.
 * 
 * This version is optimized for side-channel analysis with minimal
 * parameter setup.
 * 
 * @param[in]  key    16-byte key at key_addr
 * @param[in]  nonce  16-byte nonce at nonce_addr  
 * @param[in]  pt     16-byte plaintext at pt_addr
 * @param[out] ct     16-byte ciphertext output at ct_addr
 * @param[out] tag    16-byte tag output at tag_addr
 */
void ascon_encrypt_simple(const uint8_t *key, const uint8_t *nonce,
                          const uint8_t *pt, uint8_t *ct, uint8_t *tag) {
    Key k;
    Nonce n;
    Plaintext plaintext;
    AssociatedData ad;
    EncryptionResult *res;
    
    // Setup key
    k.msb = ((uint64_t)key[0] << 56) | ((uint64_t)key[1] << 48) |
            ((uint64_t)key[2] << 40) | ((uint64_t)key[3] << 32) |
            ((uint64_t)key[4] << 24) | ((uint64_t)key[5] << 16) |
            ((uint64_t)key[6] << 8)  | (uint64_t)key[7];
    k.lsb = ((uint64_t)key[8] << 56) | ((uint64_t)key[9] << 48) |
            ((uint64_t)key[10] << 40) | ((uint64_t)key[11] << 32) |
            ((uint64_t)key[12] << 24) | ((uint64_t)key[13] << 16) |
            ((uint64_t)key[14] << 8)  | (uint64_t)key[15];
    
    // Setup nonce
    n.msb = ((uint64_t)nonce[0] << 56) | ((uint64_t)nonce[1] << 48) |
            ((uint64_t)nonce[2] << 40) | ((uint64_t)nonce[3] << 32) |
            ((uint64_t)nonce[4] << 24) | ((uint64_t)nonce[5] << 16) |
            ((uint64_t)nonce[6] << 8)  | (uint64_t)nonce[7];
    n.lsb = ((uint64_t)nonce[8] << 56) | ((uint64_t)nonce[9] << 48) |
            ((uint64_t)nonce[10] << 40) | ((uint64_t)nonce[11] << 32) |
            ((uint64_t)nonce[12] << 24) | ((uint64_t)nonce[13] << 16) |
            ((uint64_t)nonce[14] << 8)  | (uint64_t)nonce[15];
    
    // Setup plaintext (single block)
    pt_block.msb = ((uint64_t)pt[0] << 56) | ((uint64_t)pt[1] << 48) |
                   ((uint64_t)pt[2] << 40) | ((uint64_t)pt[3] << 32) |
                   ((uint64_t)pt[4] << 24) | ((uint64_t)pt[5] << 16) |
                   ((uint64_t)pt[6] << 8)  | (uint64_t)pt[7];
    pt_block.lsb = ((uint64_t)pt[8] << 56) | ((uint64_t)pt[9] << 48) |
                   ((uint64_t)pt[10] << 40) | ((uint64_t)pt[11] << 32) |
                   ((uint64_t)pt[12] << 24) | ((uint64_t)pt[13] << 16) |
                   ((uint64_t)pt[14] << 8)  | (uint64_t)pt[15];
    
    plaintext.size = 1;
    plaintext.arr = &pt_block;
    
    // Empty associated data
    ad.size = 0;
    ad.arr = NULL;
    
    // Initialize result storage
    result.ciphertext.size = 1;
    result.ciphertext.arr = &ct_block;
    
    // Call encryption directly (bypassing malloc)
    State s;
    init_state(&s, &k, &n);
    p12(&s);
    s.s3 ^= k.msb;
    s.s4 ^= k.lsb;
    s.s4 ^= 1;  // domain separation
    
    // Process plaintext
    s.s0 ^= pt_block.msb;
    s.s1 ^= pt_block.lsb;
    ct_block.msb = s.s0;
    ct_block.lsb = s.s1;
    p6(&s);
    
    // Finalization
    s.s2 ^= k.msb;
    s.s3 ^= k.lsb;
    p12(&s);
    result.tag.msb = s.s3 ^ k.msb;
    result.tag.lsb = s.s4 ^ k.lsb;
    
    // Copy output
    ct[0] = (ct_block.msb >> 56) & 0xFF;
    ct[1] = (ct_block.msb >> 48) & 0xFF;
    ct[2] = (ct_block.msb >> 40) & 0xFF;
    ct[3] = (ct_block.msb >> 32) & 0xFF;
    ct[4] = (ct_block.msb >> 24) & 0xFF;
    ct[5] = (ct_block.msb >> 16) & 0xFF;
    ct[6] = (ct_block.msb >> 8) & 0xFF;
    ct[7] = ct_block.msb & 0xFF;
    ct[8] = (ct_block.lsb >> 56) & 0xFF;
    ct[9] = (ct_block.lsb >> 48) & 0xFF;
    ct[10] = (ct_block.lsb >> 40) & 0xFF;
    ct[11] = (ct_block.lsb >> 32) & 0xFF;
    ct[12] = (ct_block.lsb >> 24) & 0xFF;
    ct[13] = (ct_block.lsb >> 16) & 0xFF;
    ct[14] = (ct_block.lsb >> 8) & 0xFF;
    ct[15] = ct_block.lsb & 0xFF;
    
    tag[0] = (result.tag.msb >> 56) & 0xFF;
    tag[1] = (result.tag.msb >> 48) & 0xFF;
    tag[2] = (result.tag.msb >> 40) & 0xFF;
    tag[3] = (result.tag.msb >> 32) & 0xFF;
    tag[4] = (result.tag.msb >> 24) & 0xFF;
    tag[5] = (result.tag.msb >> 16) & 0xFF;
    tag[6] = (result.tag.msb >> 8) & 0xFF;
    tag[7] = result.tag.msb & 0xFF;
    tag[8] = (result.tag.lsb >> 56) & 0xFF;
    tag[9] = (result.tag.lsb >> 48) & 0xFF;
    tag[10] = (result.tag.lsb >> 40) & 0xFF;
    tag[11] = (result.tag.lsb >> 32) & 0xFF;
    tag[12] = (result.tag.lsb >> 24) & 0xFF;
    tag[13] = (result.tag.lsb >> 16) & 0xFF;
    tag[14] = (result.tag.lsb >> 8) & 0xFF;
    tag[15] = result.tag.lsb & 0xFF;
}

// Keep attribute to prevent optimization
void ascon_encrypt_simple(const uint8_t *, const uint8_t *, const uint8_t *, uint8_t *, uint8_t *) __attribute__((used));

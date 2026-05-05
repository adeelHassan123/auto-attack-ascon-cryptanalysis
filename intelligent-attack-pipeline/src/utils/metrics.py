"""Metrics and helper functions for side-channel analysis."""
import numpy as np


# Precomputed Hamming Weight table for 5-bit values (ASCON S-box)
HW_TABLE_5BIT = np.array([
    0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5
], dtype=np.int32)


def hamming_weight_5bit(value):
    """Calculate Hamming Weight for 5-bit ASCON S-box output.
    
    Args:
        value: Integer 0-31 (5-bit value)
    
    Returns:
        Hamming weight 0-5 (count of '1' bits)
    """
    return HW_TABLE_5BIT[value & 0x1F]


def hamming_weight_5bit_array(arr):
    """Calculate Hamming Weight for array of 5-bit values.
    
    Args:
        arr: Array of integers 0-31
    
    Returns:
        Array of Hamming weights 0-5
    """
    return HW_TABLE_5BIT[np.array(arr, dtype=np.int32) & 0x1F]


def hamming_weight(arr):
    """Calculate Hamming Weight of array values (8-bit)."""
    return np.array([bin(int(v)).count('1') for v in arr], dtype=np.int32)


def hamming_weight_byte(byte_val):
    """Calculate Hamming Weight of a single byte."""
    return bin(int(byte_val)).count('1')


# ASCON S-box lookup table (5-bit to 5-bit)
# From NIST SP 800-232 specification
ASCON_SBOX = np.array([
    0x04, 0x0b, 0x1e, 0x15, 0x1a, 0x11, 0x06, 0x0d,
    0x08, 0x03, 0x12, 0x19, 0x14, 0x1f, 0x0a, 0x01,
    0x1c, 0x17, 0x02, 0x09, 0x10, 0x1b, 0x0e, 0x05,
    0x18, 0x13, 0x00, 0x07, 0x0c, 0x1d, 0x16, 0x0f
], dtype=np.uint8)


# Precompute ASCON S-box HW for all possible 5-bit inputs
ASCON_SBOX_HW = np.array([hamming_weight_5bit(v) for v in ASCON_SBOX], dtype=np.int32)


def compute_ascon_sbox_hw(pt_byte, key_byte, nonce_byte=0):
    """Compute ASCON S-box output Hamming Weight for first round.
    
    This simulates the first round of ASCON initialization where the
    key and plaintext are injected into the state and the S-box is applied.
    
    For a single byte attack, we model the leakage as:
    - State x0 (IV) contributes constant
    - State x1 (key) contributes key_byte
    - State x3 (nonce) contributes nonce_byte
    - S-box operates on 5-bit column: (iv_bit, key_bit, key_bit2, nonce_bit, nonce_bit2)
    
    Simplified model for first byte (LSB column):
    sbox_input = (pt_byte ^ key_byte ^ nonce_byte) & 0x1F  # Lower 5 bits
    sbox_output = ASCON_SBOX[sbox_input]
    hw = hamming_weight_5bit(sbox_output)
    
    Args:
        pt_byte: Plaintext byte (0-255)
        key_byte: Key byte (0-255)
        nonce_byte: Nonce byte (0-255), default 0
    
    Returns:
        Hamming Weight of S-box output (0-5)
    """
    # For the first byte, the simplified first-round S-box input uses
    # plaintext, key, and nonce contributions in a consistent leakage model.
    sbox_input = int((pt_byte ^ key_byte ^ nonce_byte) & 0x1F)
    
    # Apply ASCON S-box
    sbox_output = int(ASCON_SBOX[sbox_input])
    
    # Return Hamming Weight of 5-bit output
    return hamming_weight_5bit(sbox_output)


def compute_ascon_sbox_hw_batch(pt_bytes, key_bytes, nonce_bytes=None):
    """Batch compute ASCON S-box HW for arrays.
    
    Args:
        pt_bytes: Array of plaintext bytes
        key_bytes: Array of key bytes
        nonce_bytes: Array of nonce bytes (optional)
    
    Returns:
        Array of Hamming Weights (0-5)
    """
    if nonce_bytes is None:
        nonce_bytes = np.zeros_like(pt_bytes)
    
    # Vectorized computation (same model as compute_ascon_sbox_hw)
    sbox_inputs = (pt_bytes ^ key_bytes ^ nonce_bytes) & 0x1F
    sbox_outputs = ASCON_SBOX[sbox_inputs]
    hws = ASCON_SBOX_HW[sbox_outputs]
    
    return hws


def verify_hw_distribution(labels, tolerance=2.0):
    """Verify that HW distribution matches expected binomial.
    
    Args:
        labels: Array of HW labels (0-5)
        tolerance: Percentage tolerance (default 2.0%)
    
    Returns:
        bool: True if distribution is valid
    """
    # Expected binomial distribution for 5-bit uniform random
    expected = np.array([3.125, 15.625, 31.25, 31.25, 15.625, 3.125])
    
    # Actual distribution
    counts = np.bincount(labels, minlength=6)
    actual = counts / len(labels) * 100
    
    # Check within tolerance
    diff = np.abs(actual - expected)
    valid = np.all(diff <= tolerance)
    
    if not valid:
        print(f"WARNING: HW distribution deviates from expected:")
        print(f"  Expected: {expected}")
        print(f"  Actual:   {actual}")
        print(f"  Diff:     {diff}")
    
    return valid

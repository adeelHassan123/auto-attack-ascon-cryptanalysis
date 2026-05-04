"""Metrics and helper functions for side-channel analysis."""
import numpy as np


def hamming_weight(arr):
    """Calculate Hamming Weight of array values."""
    return np.array([bin(int(v)).count('1') for v in arr], dtype=np.int32)


def hamming_weight_byte(byte_val):
    """Calculate Hamming Weight of a single byte."""
    return bin(int(byte_val)).count('1')

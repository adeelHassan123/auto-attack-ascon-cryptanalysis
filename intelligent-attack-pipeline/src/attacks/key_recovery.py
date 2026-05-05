"""Key recovery algorithms for ASCON-128 side-channel attacks."""
import numpy as np
from ..utils.metrics import (
    hamming_weight, hamming_weight_5bit_array, HW_TABLE_5BIT,
    compute_ascon_sbox_hw, ASCON_SBOX, hamming_weight_5bit
)


# Precompute key recovery lookup table for speed
# For each (plaintext_byte, key_guess) pair, store the ASCON S-box HW
# This assumes nonce=0 for simplicity; in full implementation, include nonce
KEY_RECOVERY_HW_TABLE = np.zeros((256, 256), dtype=np.uint8)
for pt in range(256):
    for k in range(256):
        KEY_RECOVERY_HW_TABLE[pt, k] = compute_ascon_sbox_hw(pt, k, 0)


def generate_labels(pt, key, nonce=None, target_byte=0, use_ascon_sbox=True):
    """Generate Hamming Weight labels for training.
    
    Args:
        pt: Plaintext array (N, 16)
        key: Key array (N, 16)
        nonce: Nonce array (N, 16), optional
        target_byte: Which byte to attack (0-15)
        use_ascon_sbox: If True, use ASCON 5-bit S-box HW (0-5)
                       If False, use 8-bit HW (0-8)
    
    Returns:
        Hamming weight array (0-5 for ASCON)
    """
    if use_ascon_sbox:
        if nonce is None:
            # Backward-compatible fast path
            return np.array([
                KEY_RECOVERY_HW_TABLE[int(p), int(k)]
                for p, k in zip(pt[:, target_byte], key[:, target_byte])
            ])
        return np.array([
            compute_ascon_sbox_hw(int(p), int(k), int(n))
            for p, k, n in zip(pt[:, target_byte], key[:, target_byte], nonce[:, target_byte])
        ], dtype=np.uint8)
    else:
        # Standard 8-bit Hamming Weight (for comparison only)
        intermediate = np.bitwise_xor(pt[:, target_byte], key[:, target_byte])
        return hamming_weight(intermediate)


def key_recovery_from_predictions(predictions, pt, true_key_byte, nonce=None, target_byte=0, num_classes=6):
    """Perform key recovery from model predictions (fixed-key scenario).
    
    Args:
        predictions: Model predictions (num_traces, num_classes)
        pt: Plaintext array (num_traces, 16)
        true_key_byte: The actual key byte value
        nonce: Nonce array (num_traces, 16), optional
        target_byte: Which byte to recover (0-15)
        num_classes: Number of HW classes (6 for ASCON 5-bit S-box, 9 for 8-bit)
    
    Returns:
        rank: Position of correct key in sorted candidates
        key_scores: Score for each key hypothesis (256)
    """
    num_traces = pt.shape[0]
    key_scores = np.zeros(256, dtype=np.float64)
    
    for k in range(256):
        if num_classes == 6:
            if nonce is None:
                # Backward-compatible path
                intermediate = np.bitwise_xor(pt[:, target_byte], k) & 0x1F
            else:
                intermediate = (pt[:, target_byte] ^ k ^ nonce[:, target_byte]) & 0x1F
            hw_hyp = hamming_weight_5bit_array(intermediate)
        else:
            # Standard 8-bit Hamming Weight
            hw_hyp = hamming_weight(np.bitwise_xor(pt[:, target_byte], k))
        
        probs = predictions[np.arange(num_traces), hw_hyp]
        key_scores[k] = np.sum(np.log(probs + 1e-36))
    
    rank = np.argsort(-key_scores)
    true_rank = np.where(rank == int(true_key_byte))[0][0]
    
    return int(true_rank), key_scores


def per_trace_variable_key_success(predictions, pt, key_bytes, nonce=None, target_byte=0, num_classes=6):
    """Evaluate success for variable-key scenario (per-trace key recovery).
    
    Args:
        predictions: Model predictions (N, num_classes)
        pt: Plaintext array (N, 16)
        key_bytes: True key bytes for each trace (N, 16)
        nonce: Nonce array (N, 16), optional
        target_byte: Which byte to recover (0-15)
        num_classes: Number of HW classes (6 for ASCON, 9 for 8-bit)
    
    Returns:
        ranks: Rank of correct key for each trace
    """
    n = pt.shape[0]
    ranks = np.zeros(n, dtype=np.int32)
    
    for i in range(n):
        score = np.zeros(256, dtype=np.float64)
        for k in range(256):
            if num_classes == 6:
                if nonce is None:
                    intermediate = (int(pt[i, target_byte]) ^ k) & 0x1F
                else:
                    intermediate = (int(pt[i, target_byte]) ^ k ^ int(nonce[i, target_byte])) & 0x1F
                hw = HW_TABLE_5BIT[intermediate]
            else:
                # Standard 8-bit HW
                hw = bin(int(pt[i, target_byte] ^ k)).count('1')
            
            score[k] = np.log(predictions[i, hw] + 1e-36)
        
        rank = np.argsort(-score)
        ranks[i] = np.where(rank == int(key_bytes[i, target_byte]))[0][0]
    
    return ranks


def rank_to_success_rate(ranks, max_rank=0):
    """Convert ranks array to success rate.
    
    Args:
        ranks: Array of key ranks (0 = correct key is top guess)
        max_rank: Maximum rank to consider as success (default 0 = only rank 0)
    
    Returns:
        success_rate: Fraction of traces where rank <= max_rank
    """
    return np.mean(ranks <= max_rank)


def rank_statistics(ranks):
    """Compute comprehensive rank statistics.
    
    Args:
        ranks: Array of key ranks
    
    Returns:
        dict: Statistics including mean, median, success rate, etc.
    """
    return {
        'mean_rank': float(np.mean(ranks)),
        'median_rank': float(np.median(ranks)),
        'std_rank': float(np.std(ranks)),
        'min_rank': int(np.min(ranks)),
        'max_rank': int(np.max(ranks)),
        'success_rate_rank0': float(rank_to_success_rate(ranks, 0)),
        'success_rate_rank5': float(rank_to_success_rate(ranks, 5)),
        'success_rate_rank10': float(rank_to_success_rate(ranks, 10)),
        'num_traces': len(ranks)
    }


def key_recovery_by_byte(predictions, pt, key_bytes, target_byte=0, 
                        leakage_model='ascon', num_classes=6):
    """Comprehensive key recovery with ASCON leakage model.
    
    Args:
        predictions: Model predictions (N, num_classes)
        pt: Plaintext array (N, 16)
        key_bytes: True key bytes (N, 16) or single key
        target_byte: Which byte to attack (0-15)
        leakage_model: 'ascon' or 'xor'
        num_classes: Number of HW classes
    
    Returns:
        ranks: Array of ranks (for variable-key) or single rank (for fixed-key)
        scores: Key scores matrix
    """
    n = pt.shape[0]
    is_fixed_key = len(key_bytes.shape) == 1 or np.all(key_bytes == key_bytes[0])
    
    if is_fixed_key:
        # Fixed-key scenario
        true_key = key_bytes[0, target_byte] if len(key_bytes.shape) > 1 else key_bytes[target_byte]
        rank, scores = key_recovery_from_predictions(
            predictions, pt, true_key, num_classes=num_classes
        )
        return np.array([rank]), scores
    else:
        # Variable-key scenario
        ranks = per_trace_variable_key_success(
            predictions, pt, key_bytes, num_classes=num_classes
        )
        # Compute average scores for reporting
        scores = None  # Not meaningful for variable-key
        return ranks, scores

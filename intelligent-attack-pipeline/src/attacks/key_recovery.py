"""Key recovery algorithms for side-channel attacks."""
import numpy as np
from ..utils.metrics import hamming_weight


def generate_labels(pt, key, target_byte=0):
    """Generate Hamming Weight labels for training.
    
    Args:
        pt: Plaintext array (N, 16)
        key: Key array (N, 16)
        target_byte: Which byte to attack (0-15)
    
    Returns:
        Hamming weight of intermediate value (pt XOR key)
    """
    intermediate = np.bitwise_xor(pt[:, target_byte], key[:, target_byte])
    return hamming_weight(intermediate)


def key_recovery_from_predictions(predictions, pt, true_key_byte):
    """Perform key recovery from model predictions (fixed-key scenario).
    
    Args:
        predictions: Model predictions (num_traces, num_classes)
        pt: Plaintext array (num_traces, 16)
        true_key_byte: The actual key byte value
    
    Returns:
        rank: Position of correct key in sorted candidates
        key_scores: Score for each key hypothesis (256)
    """
    num_traces = pt.shape[0]
    key_scores = np.zeros(256, dtype=np.float64)
    
    for k in range(256):
        hw_hyp = hamming_weight(np.bitwise_xor(pt[:, 0], k))
        probs = predictions[np.arange(num_traces), hw_hyp]
        key_scores[k] = np.sum(np.log(probs + 1e-36))
    
    rank = np.argsort(-key_scores)
    true_rank = np.where(rank == int(true_key_byte))[0][0]
    
    return int(true_rank), key_scores


def per_trace_variable_key_success(predictions, pt, key_bytes):
    """Evaluate success for variable-key scenario (per-trace key recovery).
    
    Args:
        predictions: Model predictions (N, num_classes)
        pt: Plaintext array (N, 16)
        key_bytes: True key bytes for each trace (N, 16)
    
    Returns:
        ranks: Rank of correct key for each trace
    """
    n = pt.shape[0]
    ranks = np.zeros(n, dtype=np.int32)
    
    for i in range(n):
        score = np.zeros(256, dtype=np.float64)
        for k in range(256):
            hw = bin(int(pt[i, 0] ^ k)).count('1')
            score[k] = np.log(predictions[i, hw] + 1e-36)
        
        rank = np.argsort(-score)
        ranks[i] = np.where(rank == int(key_bytes[i, 0]))[0][0]
    
    return ranks

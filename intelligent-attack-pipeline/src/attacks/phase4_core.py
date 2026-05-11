"""Phase 4 core functions for ASCON-128 deep-learning attacks."""
import random
import numpy as np

from src.attacks.key_recovery import compute_ascon_sbox_hw_full, rank_statistics
from src.utils.metrics_fixed import compute_ascon_sbox_hw


def set_global_seeds(seed=42):
    """Set deterministic seeds used across Phase 4 scripts."""
    random.seed(seed)
    np.random.seed(seed)
    try:
        import tensorflow as tf
        tf.random.set_seed(seed)
    except Exception:
        pass


def ensure_trace_length(traces, target_len=1551):
    """Pad/truncate trace matrix to fixed length expected by models."""
    x = np.asarray(traces, dtype=np.float32)
    if x.ndim != 2:
        raise ValueError(f"Expected 2D traces, got shape {x.shape}")
    n, m = x.shape
    if m == target_len:
        return x
    if m > target_len:
        return x[:, :target_len]
    out = np.zeros((n, target_len), dtype=np.float32)
    out[:, :m] = x
    if m > 0:
        out[:, m:] = x[:, [m - 1]]
    return out


def compute_ascon_first_round_hw(
    key_byte,
    nonce,
    plaintext_byte,
    target_byte_position=0,
    key_template=None,
):
    """Compute 5-bit HW after ASCON first-round S-box for one trace hypothesis.

    Args:
        key_byte: Hypothesized key byte value for target byte.
        nonce: 16-byte nonce for this trace.
        plaintext_byte: Present for API compatibility (init leakage does not use it).
        target_byte_position: Target key byte index (0..15).
        key_template: Optional full 16-byte key template. If given, all bytes except
            the target byte are copied from this template.

    Returns:
        int in [0, 5]
    """
    _ = plaintext_byte  # Not used by ASCON init leakage for this target.
    if key_template is None:
        key_full = np.zeros(16, dtype=np.uint8)
    else:
        key_full = np.array(key_template, dtype=np.uint8, copy=True)
        if key_full.shape != (16,):
            raise ValueError(f"key_template must be 16 bytes, got shape {key_full.shape}")

    key_full[int(target_byte_position)] = np.uint8(key_byte)
    nonce_arr = np.array(nonce, dtype=np.uint8, copy=False)
    if nonce_arr.shape != (16,):
        raise ValueError(f"nonce must be 16 bytes, got shape {nonce_arr.shape}")

    return int(compute_ascon_sbox_hw_full(key_full, nonce_arr, column=int(target_byte_position) * 8, rounds=0))


def generate_hw_labels(keys, nonces, plaintexts, target_byte=0, rounds=0):
    """Generate HW labels from metadata using the corrected ASCON model."""
    keys = np.asarray(keys, dtype=np.uint8)
    nonces = np.asarray(nonces, dtype=np.uint8)
    plaintexts = np.asarray(plaintexts, dtype=np.uint8)
    n = keys.shape[0]
    labels = np.zeros(n, dtype=np.uint8)
    for i in range(n):
        labels[i] = compute_ascon_sbox_hw(
            keys[i], nonces[i], column=target_byte * 8, rounds=rounds
        )
    return labels


def recover_key_byte(predictions, plaintexts, nonces, true_key_byte, target_byte=0, key_templates=None, rounds=0):
    """Recover one key byte using profile model probabilities (OPTIMIZED with Numba).

    Args:
        predictions: Model output probabilities shape (N, 6).
        plaintexts: Attack plaintexts shape (N, 16).
        nonces: Attack nonces shape (N, 16).
        true_key_byte: Ground-truth value for target byte.
        target_byte: Byte index to recover (0..15).
        key_templates: Full-key templates per trace shape (N, 16) or (16,).

    Returns:
        (rank, key_scores) where key_scores has shape (256,)
    """
    from src.attacks.key_recovery import compute_ascon_sbox_hw_fast
    
    predictions = np.asarray(predictions, dtype=np.float64)
    plaintexts = np.asarray(plaintexts, dtype=np.uint8)
    nonces = np.asarray(nonces, dtype=np.uint8)
    if key_templates is None:
        key_templates = np.zeros((predictions.shape[0], 16), dtype=np.uint8)
    key_templates = np.asarray(key_templates, dtype=np.uint8)
    if key_templates.ndim == 1:
        key_templates = np.tile(key_templates, (predictions.shape[0], 1))

    n = predictions.shape[0]
    key_scores = np.zeros(256, dtype=np.float64)
    idx = np.arange(n)
    target_column = target_byte * 8

    # OPTIMIZED: Use Numba-accelerated HW computation
    print(f"  Evaluating {n} attack traces against 256 key hypotheses (Numba-accelerated)...")
    for k_guess in range(256):
        score = 0.0
        for i in range(n):
            # Create key hypothesis
            key_hyp = key_templates[i].copy()
            key_hyp[target_byte] = k_guess
            # Fast HW computation
            hw = compute_ascon_sbox_hw_fast(key_hyp, nonces[i], column=target_column, rounds=rounds)
            score += np.log(predictions[i, hw] + 1e-36)
        key_scores[k_guess] = score
        
        if k_guess % 64 == 0:
            print(f"    Progress: {k_guess}/256 key hypotheses")

    order = np.argsort(-key_scores)
    rank = int(np.where(order == int(true_key_byte))[0][0])
    print(f"    Attack complete - true key rank: {rank}")
    return rank, key_scores


def recover_variable_key_ranks(predictions, plaintexts, nonces, true_keys, target_byte=0, rounds=0):
    """Per-trace key recovery ranks in variable-key scenario (OPTIMIZED with Numba)."""
    from src.attacks.key_recovery import compute_ascon_sbox_hw_fast
    
    predictions = np.asarray(predictions, dtype=np.float64)
    plaintexts = np.asarray(plaintexts, dtype=np.uint8)
    nonces = np.asarray(nonces, dtype=np.uint8)
    true_keys = np.asarray(true_keys, dtype=np.uint8)

    n = predictions.shape[0]
    target_column = target_byte * 8
    ranks = np.zeros(n, dtype=np.int32)
    
    print(f"  Evaluating variable-key attack for {n} traces (Numba-accelerated)...")
    for i in range(n):
        score = np.zeros(256, dtype=np.float64)
        key_template = true_keys[i].copy()
        
        for k_guess in range(256):
            key_template[target_byte] = k_guess
            # Fast HW computation with Numba
            hw = compute_ascon_sbox_hw_fast(key_template, nonces[i], column=target_column, rounds=rounds)
            score[k_guess] = np.log(predictions[i, hw] + 1e-36)
            
        order = np.argsort(-score)
        ranks[i] = int(np.where(order == int(true_keys[i, target_byte]))[0][0])
        
        if i % 500 == 0 and i > 0:
            print(f"    Progress: {i}/{n} traces processed")
    
    print(f"    Variable-key attack complete - mean rank: {np.mean(ranks):.1f}")
    return ranks


def guessing_entropy_bits_from_ranks(ranks):
    """Guessing entropy in bits from rank array."""
    ranks = np.asarray(ranks, dtype=np.float64)
    return float(np.mean(np.log2(ranks + 1.0)))


def summarize_variable_ranks(ranks):
    """Rank summary for report tables."""
    stats = rank_statistics(ranks)
    stats["guessing_entropy_bits"] = guessing_entropy_bits_from_ranks(ranks)
    return stats


def self_test_phase4_core():
    """Sanity checks: label path and Numba attack path must agree."""
    from src.attacks.key_recovery import compute_ascon_sbox_hw_fast, compute_ascon_sbox_hw_full

    hw = compute_ascon_first_round_hw(0x00, np.zeros(16, dtype=np.uint8), 0x00, target_byte_position=0)
    assert 0 <= hw <= 5

    rng = np.random.default_rng(12345)
    for _ in range(32):
        key = rng.integers(0, 256, 16, dtype=np.uint8)
        nonce = rng.integers(0, 256, 16, dtype=np.uint8)
        for col in (0, 8, 24, 40, 56):
            a = int(compute_ascon_sbox_hw_full(key, nonce, col, 0))
            b = int(compute_ascon_sbox_hw_fast(key, nonce, col, 0))
            assert a == b, f'Numba HW mismatch: full={a} fast={b} col={col}'

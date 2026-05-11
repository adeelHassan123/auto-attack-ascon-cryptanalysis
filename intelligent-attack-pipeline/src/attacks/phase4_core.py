"""Phase 4 core functions for ASCON-128 deep-learning attacks."""
import random
import numpy as np

from src.attacks.key_recovery import compute_ascon_sbox_hw_full, rank_statistics


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

    return int(compute_ascon_sbox_hw_full(key_full, nonce_arr, column=int(target_byte_position) * 8))


def generate_hw_labels(keys, nonces, plaintexts, target_byte=0):
    """Generate HW labels from metadata using the corrected ASCON model."""
    keys = np.asarray(keys, dtype=np.uint8)
    nonces = np.asarray(nonces, dtype=np.uint8)
    plaintexts = np.asarray(plaintexts, dtype=np.uint8)
    n = keys.shape[0]
    labels = np.zeros(n, dtype=np.uint8)
    for i in range(n):
        labels[i] = compute_ascon_first_round_hw(
            key_byte=int(keys[i, target_byte]),
            nonce=nonces[i],
            plaintext_byte=int(plaintexts[i, target_byte]),
            target_byte_position=target_byte,
            key_template=keys[i],
        )
    return labels


def recover_key_byte(predictions, plaintexts, nonces, true_key_byte, target_byte=0, key_templates=None):
    """Recover one key byte using profile model probabilities.

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

    for k_guess in range(256):
        hyp_hw = np.zeros(n, dtype=np.uint8)
        for i in range(n):
            hyp_hw[i] = compute_ascon_first_round_hw(
                key_byte=k_guess,
                nonce=nonces[i],
                plaintext_byte=int(plaintexts[i, target_byte]),
                target_byte_position=target_byte,
                key_template=key_templates[i],
            )
        key_scores[k_guess] = np.sum(np.log(predictions[idx, hyp_hw] + 1e-36))

    order = np.argsort(-key_scores)
    rank = int(np.where(order == int(true_key_byte))[0][0])
    return rank, key_scores


def recover_variable_key_ranks(predictions, plaintexts, nonces, true_keys, target_byte=0):
    """Per-trace key recovery ranks in variable-key scenario."""
    predictions = np.asarray(predictions, dtype=np.float64)
    plaintexts = np.asarray(plaintexts, dtype=np.uint8)
    nonces = np.asarray(nonces, dtype=np.uint8)
    true_keys = np.asarray(true_keys, dtype=np.uint8)

    n = predictions.shape[0]
    ranks = np.zeros(n, dtype=np.int32)
    for i in range(n):
        score = np.zeros(256, dtype=np.float64)
        for k_guess in range(256):
            hw = compute_ascon_first_round_hw(
                key_byte=k_guess,
                nonce=nonces[i],
                plaintext_byte=int(plaintexts[i, target_byte]),
                target_byte_position=target_byte,
                key_template=true_keys[i],
            )
            score[k_guess] = np.log(predictions[i, hw] + 1e-36)
        order = np.argsort(-score)
        ranks[i] = int(np.where(order == int(true_keys[i, target_byte]))[0][0])
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
    """One-line sanity checks required by the audit prompt."""
    hw = compute_ascon_first_round_hw(0x00, np.zeros(16, dtype=np.uint8), 0x00, target_byte_position=0)
    assert 0 <= hw <= 5

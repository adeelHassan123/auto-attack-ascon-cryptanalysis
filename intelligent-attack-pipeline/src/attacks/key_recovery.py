"""Key recovery algorithms for ASCON-128 side-channel attacks.

CRITICAL FIX: This module now uses proper ASCON-128 state simulation for key recovery.
The previous AES-style XOR model has been completely replaced with actual sponge
construction state tracking.
"""
import numpy as np

# Try to import Numba for JIT acceleration
try:
    from numba import njit, prange
    NUMBA_AVAILABLE = True
except ImportError:
    NUMBA_AVAILABLE = False
    # Create dummy decorators if numba not available
    def njit(*args, **kwargs):
        def decorator(func):
            return func
        return decorator
    prange = range

# ASCON-128 S-box (5-bit to 5-bit) - NIST SP 800-232
ASCON_SBOX = np.array([
    0x04, 0x0b, 0x1f, 0x14, 0x1a, 0x15, 0x09, 0x02,
    0x1b, 0x05, 0x08, 0x12, 0x1d, 0x03, 0x06, 0x1c,
    0x1e, 0x13, 0x07, 0x0e, 0x00, 0x0d, 0x11, 0x18,
    0x10, 0x0c, 0x01, 0x19, 0x16, 0x0a, 0x0f, 0x17
], dtype=np.uint8)

# Hamming weight for 5-bit values
HW5_TABLE = np.array([
    0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5
], dtype=np.uint8)

# Round constants for p12 (rounds 0-11)
RC = np.array([
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
    0x78, 0x69, 0x5a, 0x4b
], dtype=np.uint64)

# ASCON-128 IV
ASCON_IV = np.uint64(0x80400c0600000000)


def ascon_init_state(key, nonce):
    """Initialize ASCON state with key and nonce.
    
    State layout: x0=IV, x1=key[0:8], x2=key[8:16], x3=nonce[0:8], x4=nonce[8:16]
    
    Args:
        key: 16-byte array
        nonce: 16-byte array
    
    Returns:
        5-element uint64 array representing state
    """
    state = np.zeros(5, dtype=np.uint64)
    state[0] = ASCON_IV
    state[1] = (np.uint64(key[0]) << 56) | (np.uint64(key[1]) << 48) | \
               (np.uint64(key[2]) << 40) | (np.uint64(key[3]) << 32) | \
               (np.uint64(key[4]) << 24) | (np.uint64(key[5]) << 16) | \
               (np.uint64(key[6]) << 8) | np.uint64(key[7])
    state[2] = (np.uint64(key[8]) << 56) | (np.uint64(key[9]) << 48) | \
               (np.uint64(key[10]) << 40) | (np.uint64(key[11]) << 32) | \
               (np.uint64(key[12]) << 24) | (np.uint64(key[13]) << 16) | \
               (np.uint64(key[14]) << 8) | np.uint64(key[15])
    state[3] = (np.uint64(nonce[0]) << 56) | (np.uint64(nonce[1]) << 48) | \
               (np.uint64(nonce[2]) << 40) | (np.uint64(nonce[3]) << 32) | \
               (np.uint64(nonce[4]) << 24) | (np.uint64(nonce[5]) << 16) | \
               (np.uint64(nonce[6]) << 8) | np.uint64(nonce[7])
    state[4] = (np.uint64(nonce[8]) << 56) | (np.uint64(nonce[9]) << 48) | \
               (np.uint64(nonce[10]) << 40) | (np.uint64(nonce[11]) << 32) | \
               (np.uint64(nonce[12]) << 24) | (np.uint64(nonce[13]) << 16) | \
               (np.uint64(nonce[14]) << 8) | np.uint64(nonce[15])
    return state


def rotr(x, n):
    """64-bit rotate right."""
    return np.uint64((x >> n) | (x << (64 - n)))


def ascon_sbox(state):
    """Apply ASCON S-box layer (bit-sliced across 5 words).
    
    Uses lookup table approach for clarity.
    """
    new_state = np.zeros(5, dtype=np.uint64)
    
    # Process each of 64 bit-slices
    for i in range(64):
        # Extract 5-bit column
        col = 0
        # Keep bit order consistent with dataset labels:
        # state[0] -> bit 4 (MSB) ... state[4] -> bit 0 (LSB)
        col |= int((state[0] >> i) & 1) << 4
        col |= int((state[1] >> i) & 1) << 3
        col |= int((state[2] >> i) & 1) << 2
        col |= int((state[3] >> i) & 1) << 1
        col |= int((state[4] >> i) & 1) << 0
        
        # Apply S-box
        new_col = int(ASCON_SBOX[col])
        
        # Write back
        new_state[0] |= np.uint64((new_col >> 4) & 1) << i
        new_state[1] |= np.uint64((new_col >> 3) & 1) << i
        new_state[2] |= np.uint64((new_col >> 2) & 1) << i
        new_state[3] |= np.uint64((new_col >> 1) & 1) << i
        new_state[4] |= np.uint64((new_col >> 0) & 1) << i
    
    state[:] = new_state


def ascon_linear(state):
    """Apply ASCON linear diffusion layer."""
    t = state.copy()
    state[0] = t[0] ^ rotr(t[0], 19) ^ rotr(t[0], 28)
    state[1] = t[1] ^ rotr(t[1], 61) ^ rotr(t[1], 39)
    state[2] = t[2] ^ rotr(t[2], 1) ^ rotr(t[2], 6)
    state[3] = t[3] ^ rotr(t[3], 10) ^ rotr(t[3], 17)
    state[4] = t[4] ^ rotr(t[4], 7) ^ rotr(t[4], 41)


def ascon_round(state, rnd):
    """Single ASCON permutation round."""
    # Add round constant to x2
    state[2] ^= RC[rnd]
    ascon_sbox(state)
    ascon_linear(state)


def ascon_p12(state):
    """12-round ASCON permutation (for init and finalization)."""
    for i in range(12):
        ascon_round(state, i)


def compute_ascon_sbox_hw_full(key, nonce, column=0, rounds=2):
    """Compute S-box output HW after N initialization rounds.
    
    OPTIMAL: After 2 rounds, key bits have diffused for uniform distribution.
    This replaces the broken (pt ^ key ^ nonce) formula.
    
    Args:
        key: 16-byte array
        nonce: 16-byte array
        column: Which bit-slice to target (0-63, default 0)
        rounds: Number of init rounds (default 0, optimal for first S-box)
    
    Returns:
        Hamming Weight of S-box output (0-5)
    """
    # Initialize state
    state = ascon_init_state(key, nonce)
    
    # Run N initialization rounds (optimal: 0 rounds for first S-box leakage)
    for rnd in range(rounds):
        state[2] ^= RC[rnd]  # Add round constant
        ascon_sbox(state)
        ascon_linear(state)
    
    # Extract 5-bit column AFTER rounds
    col_input = 0
    col_input |= int((state[0] >> column) & 1) << 4
    col_input |= int((state[1] >> column) & 1) << 3
    col_input |= int((state[2] >> column) & 1) << 2
    col_input |= int((state[3] >> column) & 1) << 1
    col_input |= int((state[4] >> column) & 1) << 0
    
    # Apply S-box and return HW
    sbox_out = int(ASCON_SBOX[col_input])
    return int(HW5_TABLE[sbox_out])


# =============================================================================
# Numba-accelerated fast batch computation (for attack evaluation)
# =============================================================================

if NUMBA_AVAILABLE:
    @njit(cache=True)
    def _compute_hw_fast(key0, key1, key2, key3, key4, key5, key6, key7,
                         key8, key9, key10, key11, key12, key13, key14, key15,
                         nonce0, nonce1, nonce2, nonce3, nonce4, nonce5, nonce6, nonce7,
                         nonce8, nonce9, nonce10, nonce11, nonce12, nonce13, nonce14, nonce15,
                         column, rounds):
        """Compute S-box HW for a single trace using unpacked arrays (Numba-friendly)."""
        # ASCON IV
        IV = np.uint64(0x80400c0600000000)
        
        # Round constants
        rc = np.array([0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
                       0x78, 0x69, 0x5a, 0x4b], dtype=np.uint64)
        
        # S-box table
        sbox = np.array([
            0x04, 0x0b, 0x1f, 0x14, 0x1a, 0x15, 0x09, 0x02,
            0x1b, 0x05, 0x08, 0x12, 0x1d, 0x03, 0x06, 0x1c,
            0x1e, 0x13, 0x07, 0x0e, 0x00, 0x0d, 0x11, 0x18,
            0x10, 0x0c, 0x01, 0x19, 0x16, 0x0a, 0x0f, 0x17
        ], dtype=np.uint8)
        
        # HW table
        hw5 = np.array([0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
                        1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5], dtype=np.uint8)
        
        # Build key and nonce words (must match ascon_init_state: big-endian bytes in each uint64)
        k0 = ((np.uint64(key0) << 56) | (np.uint64(key1) << 48) |
              (np.uint64(key2) << 40) | (np.uint64(key3) << 32) |
              (np.uint64(key4) << 24) | (np.uint64(key5) << 16) |
              (np.uint64(key6) << 8) | np.uint64(key7))
        k1 = ((np.uint64(key8) << 56) | (np.uint64(key9) << 48) |
              (np.uint64(key10) << 40) | (np.uint64(key11) << 32) |
              (np.uint64(key12) << 24) | (np.uint64(key13) << 16) |
              (np.uint64(key14) << 8) | np.uint64(key15))
        n0 = ((np.uint64(nonce0) << 56) | (np.uint64(nonce1) << 48) |
              (np.uint64(nonce2) << 40) | (np.uint64(nonce3) << 32) |
              (np.uint64(nonce4) << 24) | (np.uint64(nonce5) << 16) |
              (np.uint64(nonce6) << 8) | np.uint64(nonce7))
        n1 = ((np.uint64(nonce8) << 56) | (np.uint64(nonce9) << 48) |
              (np.uint64(nonce10) << 40) | (np.uint64(nonce11) << 32) |
              (np.uint64(nonce12) << 24) | (np.uint64(nonce13) << 16) |
              (np.uint64(nonce14) << 8) | np.uint64(nonce15))

        # ASCON-128 init: x0=IV, x1=k[0:8], x2=k[8:16], x3=nonce[0:8], x4=nonce[8:16]
        state0 = IV
        state1 = k0
        state2 = k1
        state3 = n0
        state4 = n1
        
        # Run rounds
        for rnd in range(rounds):
            # Add round constant
            state2 ^= rc[rnd]
            
            # S-box (bit-sliced)
            new0 = np.uint64(0)
            new1 = np.uint64(0)
            new2 = np.uint64(0)
            new3 = np.uint64(0)
            new4 = np.uint64(0)
            
            for i in range(64):
                col = np.uint8(0)
                col |= np.uint8((state0 >> i) & 1) << 4
                col |= np.uint8((state1 >> i) & 1) << 3
                col |= np.uint8((state2 >> i) & 1) << 2
                col |= np.uint8((state3 >> i) & 1) << 1
                col |= np.uint8((state4 >> i) & 1) << 0
                
                new_col = sbox[col]
                new0 |= np.uint64((new_col >> 4) & 1) << i
                new1 |= np.uint64((new_col >> 3) & 1) << i
                new2 |= np.uint64((new_col >> 2) & 1) << i
                new3 |= np.uint64((new_col >> 1) & 1) << i
                new4 |= np.uint64((new_col >> 0) & 1) << i
            
            state0, state1, state2, state3, state4 = new0, new1, new2, new3, new4
            
            # Linear layer
            t0, t1, t2, t3, t4 = state0, state1, state2, state3, state4
            state0 = t0 ^ ((t0 >> 19) | (t0 << 45)) ^ ((t0 >> 28) | (t0 << 36))
            state1 = t1 ^ ((t1 >> 61) | (t1 << 3)) ^ ((t1 >> 39) | (t1 << 25))
            state2 = t2 ^ ((t2 >> 1) | (t2 << 63)) ^ ((t2 >> 6) | (t2 << 58))
            state3 = t3 ^ ((t3 >> 10) | (t3 << 54)) ^ ((t3 >> 17) | (t3 << 47))
            state4 = t4 ^ ((t4 >> 7) | (t4 << 57)) ^ ((t4 >> 41) | (t4 << 23))
        
        # Extract column and compute HW
        col_input = np.uint8(0)
        col_input |= np.uint8((state0 >> column) & 1) << 4
        col_input |= np.uint8((state1 >> column) & 1) << 3
        col_input |= np.uint8((state2 >> column) & 1) << 2
        col_input |= np.uint8((state3 >> column) & 1) << 1
        col_input |= np.uint8((state4 >> column) & 1) << 0
        
        sbox_out = sbox[col_input]
        return hw5[sbox_out]
    
    print("[key_recovery] Numba JIT compilation enabled for fast attack evaluation")
else:
    print("[key_recovery] Numba not available, using slower Python implementation")


def generate_labels(key, nonce, num_traces=None, target_byte=0):
    """Generate Hamming Weight labels for training using REAL ASCON simulation.
    
    CRITICAL FIX: Labels are now computed using actual ASCON state initialization,
    not the broken (pt ^ key ^ nonce) XOR formula.
    
    Args:
        key: Key array (N, 16) or single key
        nonce: Nonce array (N, 16)
        num_traces: Number of traces (if key/nonce are single values)
        target_byte: Which byte to attack (0-15) - determines which bit-slice
    
    Returns:
        Hamming weight array (0-5 for ASCON 5-bit S-box)
    """
    # Ensure arrays
    if len(key.shape) == 1:
        if num_traces is None:
            raise ValueError("num_traces required when key is single value")
        key = np.tile(key, (num_traces, 1))
    
    if len(nonce.shape) == 1:
        if num_traces is None:
            raise ValueError("num_traces required when nonce is single value")
        nonce = np.tile(nonce, (num_traces, 1))
    
    n = key.shape[0]
    labels = np.zeros(n, dtype=np.uint8)
    
    # Target the bit-slice corresponding to the target byte
    # Each byte spans 8 bit-slices; we target the first slice of the byte
    target_column = target_byte * 8
    
    for i in range(n):
        labels[i] = compute_ascon_sbox_hw_full(key[i], nonce[i], target_column, rounds=2)
    
    return labels
    
    
def compute_ascon_sbox_hw_fast(key, nonce, column=0, rounds=2):
    """Fast HW computation using Numba JIT (for attack evaluation).
    
    Falls back to Python implementation if Numba not available.
    """
    if NUMBA_AVAILABLE:
        return _compute_hw_fast(
            key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
            key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15],
            nonce[0], nonce[1], nonce[2], nonce[3], nonce[4], nonce[5], nonce[6], nonce[7],
            nonce[8], nonce[9], nonce[10], nonce[11], nonce[12], nonce[13], nonce[14], nonce[15],
            column, rounds
        )
    else:
        return compute_ascon_sbox_hw_full(key, nonce, column, rounds)


def key_recovery_from_predictions(predictions, pt, true_key_byte, key_full, nonce, target_byte=0, num_classes=6):
    """Perform key recovery from model predictions (fixed-key scenario).
    
    CRITICAL FIX: Now uses actual ASCON state simulation for each key hypothesis.
    
    Args:
        predictions: Model predictions (num_traces, num_classes)
        pt: Plaintext array (num_traces, 16) - not used for HW (ASCON init doesn't use PT)
        true_key_byte: The actual key byte value
        key_full: Full 16-byte key for constructing hypotheses
        nonce: Nonce array (num_traces, 16) - REQUIRED for ASCON simulation
        target_byte: Which byte to recover (0-15)
        num_classes: Number of HW classes (6 for ASCON 5-bit S-box)
    
    Returns:
        rank: Position of correct key in sorted candidates
        key_scores: Score for each key hypothesis (256)
    """
    num_traces = pt.shape[0]
    key_scores = np.zeros(256, dtype=np.float64)
    
    # Target column corresponds to target_byte (8 bits per byte)
    target_column = target_byte * 8
    
    for k_guess in range(256):
        # Construct full key hypothesis by varying only target byte
        key_hyp = key_full.copy()
        key_hyp[target_byte] = k_guess
        
        # Compute HW for each trace using actual ASCON simulation
        hw_hyp = np.zeros(num_traces, dtype=np.uint8)
        for i in range(num_traces):
            nonce_i = nonce[i] if len(nonce.shape) > 1 else nonce
            hw_hyp[i] = compute_ascon_sbox_hw_full(key_hyp, nonce_i, target_column, rounds=2)
        
        # Accumulate log probabilities
        probs = predictions[np.arange(num_traces), hw_hyp]
        key_scores[k_guess] = np.sum(np.log(probs + 1e-36))
    
    rank = np.argsort(-key_scores)
    true_rank = np.where(rank == int(true_key_byte))[0][0]
    
    return int(true_rank), key_scores


def per_trace_variable_key_success(predictions, pt, key_bytes, nonce, target_byte=0, num_classes=6):
    """Evaluate success for variable-key scenario (per-trace key recovery).
    
    CRITICAL FIX: Now uses actual ASCON state simulation for each key hypothesis.
    
    Args:
        predictions: Model predictions (N, num_classes)
        pt: Plaintext array (N, 16) - not used for HW computation
        key_bytes: True key bytes for each trace (N, 16)
        nonce: Nonce array (N, 16) - REQUIRED
        target_byte: Which byte to recover (0-15)
        num_classes: Number of HW classes (6 for ASCON)
    
    Returns:
        ranks: Rank of correct key for each trace
    """
    n = pt.shape[0]
    ranks = np.zeros(n, dtype=np.int32)
    target_column = target_byte * 8
    
    for i in range(n):
        score = np.zeros(256, dtype=np.float64)
        true_key = key_bytes[i]
        nonce_i = nonce[i]
        
        for k_guess in range(256):
            # Construct key hypothesis
            key_hyp = true_key.copy()
            key_hyp[target_byte] = k_guess
            
            # Compute actual ASCON S-box HW
            hw = compute_ascon_sbox_hw_full(key_hyp, nonce_i, target_column, rounds=2)
            score[k_guess] = np.log(predictions[i, hw] + 1e-36)
        
        rank = np.argsort(-score)
        ranks[i] = np.where(rank == int(true_key[target_byte]))[0][0]
    
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


def key_recovery_by_byte(predictions, pt, key_bytes, nonce, target_byte=0, 
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
        key_full = key_bytes[0] if len(key_bytes.shape) > 1 else key_bytes
        rank, scores = key_recovery_from_predictions(
            predictions, pt, true_key, key_full, nonce, target_byte=target_byte, num_classes=num_classes
        )
        return np.array([rank]), scores
    else:
        # Variable-key scenario
        ranks = per_trace_variable_key_success(
            predictions, pt, key_bytes, nonce, target_byte=target_byte, num_classes=num_classes
        )
        # Compute average scores for reporting
        scores = None  # Not meaningful for variable-key
        return ranks, scores

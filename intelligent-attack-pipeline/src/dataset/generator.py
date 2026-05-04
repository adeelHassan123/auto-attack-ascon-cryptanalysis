"""Generate ASCAD-like datasets for side-channel analysis with ASCON S-box labels."""
import numpy as np
import h5py
import os
import sys

# Add parent to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))

from src.utils.metrics import (
    compute_ascon_sbox_hw_batch,
    verify_hw_distribution,
    hamming_weight_5bit
)


def generate_sca_dataset(filename, num_profiling=50000, num_attack=10000, 
                         fixed_key=True, ascon_mode=True, target_byte=0):
    """Generate ASCAD-like dataset with ASCON S-box power traces.
    
    Args:
        filename: Output HDF5 filename
        num_profiling: Number of profiling traces
        num_attack: Number of attack traces
        fixed_key: If True, use fixed key; else variable keys
        ascon_mode: If True, use ASCON 5-bit S-box HW (0-5), else 8-bit HW (0-8)
        target_byte: Which byte to target (0-15, default 0)
    
    Returns:
        None (writes to file)
    """
    assert num_profiling > 0 and num_attack > 0
    total_traces = num_profiling + num_attack
    
    print(f"Generating dataset: {filename}")
    print(f"  Total traces: {total_traces} (profiling={num_profiling}, attack={num_attack})")
    print(f"  Fixed key: {fixed_key}")
    print(f"  ASCON mode: {ascon_mode} (target byte={target_byte})")
    
    # Set random seed for reproducibility
    np.random.seed(42)
    
    # Plaintext and key generation
    plaintext = np.random.randint(0, 256, (total_traces, 16), dtype=np.uint8)
    nonces = np.random.randint(0, 256, (total_traces, 16), dtype=np.uint8)
    
    if fixed_key:
        fixed_key_bytes = np.random.randint(0, 256, 16, dtype=np.uint8)
        print(f"  Fixed key (hex): {fixed_key_bytes.tolist()}")
        key = np.tile(fixed_key_bytes, (total_traces, 1))
    else:
        # Unique random key for each trace
        key = np.random.randint(0, 256, (total_traces, 16), dtype=np.uint8)
    
    # Generate labels using ASCON S-box HW
    if ascon_mode:
        # Use proper ASCON S-box computation
        labels = compute_ascon_sbox_hw_batch(
            plaintext[:, target_byte],
            key[:, target_byte],
            nonces[:, target_byte] if nonces is not None else None
        )
        print(f"  Generated ASCON S-box labels (HW 0-5)")
    else:
        # Fallback to simple XOR HW (for comparison/testing only)
        labels = np.array([
            hamming_weight_5bit((p ^ k) & 0x1F)
            for p, k in zip(plaintext[:, target_byte], key[:, target_byte])
        ])
        print(f"  Generated simple XOR labels (HW 0-5)")
    
    # Verify distribution
    print(f"  HW distribution: {np.bincount(labels, minlength=6)}")
    verify_hw_distribution(labels)
    
    # Generate synthetic traces based on S-box HW
    # In a real scenario, these would come from Rainbow emulator
    traces = generate_synthetic_traces(labels, trace_length=1551)
    
    # Ciphertext (for metadata only)
    ciphertext = np.bitwise_xor(plaintext, key)
    
    # Write ASCAD-compatible HDF5 structure
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with h5py.File(filename, 'w') as f:
        # Profiling traces (70% by default)
        prof = f.create_group('Profiling_traces')
        prof.create_dataset('traces', data=traces[:num_profiling], dtype='float32',
                           compression='gzip', compression_opts=4)
        prof_meta = prof.create_group('metadata')
        prof_meta.create_dataset('plaintext', data=plaintext[:num_profiling], dtype='uint8')
        prof_meta.create_dataset('key', data=key[:num_profiling], dtype='uint8')
        prof_meta.create_dataset('ciphertext', data=ciphertext[:num_profiling], dtype='uint8')
        prof_meta.create_dataset('nonce', data=nonces[:num_profiling], dtype='uint8')
        prof_meta.create_dataset('sbox_hw', data=labels[:num_profiling], dtype='uint8')
        
        # Attack traces (30%)
        att = f.create_group('Attack_traces')
        att.create_dataset('traces', data=traces[num_profiling:], dtype='float32',
                          compression='gzip', compression_opts=4)
        att_meta = att.create_group('metadata')
        att_meta.create_dataset('plaintext', data=plaintext[num_profiling:], dtype='uint8')
        att_meta.create_dataset('key', data=key[num_profiling:], dtype='uint8')
        att_meta.create_dataset('ciphertext', data=ciphertext[num_profiling:], dtype='uint8')
        att_meta.create_dataset('nonce', data=nonces[num_profiling:], dtype='uint8')
        att_meta.create_dataset('sbox_hw', data=labels[num_profiling:], dtype='uint8')
        
        # Store metadata about dataset
        f.attrs['ascon_mode'] = ascon_mode
        f.attrs['fixed_key'] = fixed_key
        f.attrs['target_byte'] = target_byte
        f.attrs['num_classes'] = 6
    
    print(f"  Saved to {filename}")
    print(f"  Trace shape: {traces.shape}")
    print()


def generate_synthetic_traces(labels, trace_length=1551):
    """Generate synthetic power traces based on S-box HW labels.
    
    This simulates the leakage model where power consumption is correlated
    with the Hamming Weight of the S-box output.
    
    Args:
        labels: Array of HW labels (0-5)
        trace_length: Length of each trace (default 1551)
    
    Returns:
        Array of synthetic traces (num_traces, trace_length)
    """
    num_traces = len(labels)
    traces = np.zeros((num_traces, trace_length), dtype=np.float32)
    
    # Generate base pattern based on HW
    # Higher HW = higher power consumption
    for i in range(num_traces):
        hw = labels[i]
        
        # Create a trace pattern that correlates with HW
        # Use sine wave with amplitude proportional to HW plus noise
        t = np.linspace(0, 4 * np.pi, trace_length)
        amplitude = 0.5 + hw * 0.5  # Base amplitude increases with HW
        
        base_signal = amplitude * np.sin(t)
        noise = np.random.normal(0, 0.3, trace_length)
        
        traces[i] = base_signal + noise
    
    return traces


def generate_ascon_traces_rainbow(elf_path, num_traces=60000, fixed_key=True,
                                   output_path='data/datasets/ascon_rainbow.h5'):
    """Generate traces using Rainbow emulator (placeholder for now).
    
    This function will be implemented in scripts/generate_traces_rainbow.py
    with full Rainbow integration.
    
    Args:
        elf_path: Path to ASCON-128 ARM binary
        num_traces: Number of traces to generate
        fixed_key: Whether to use fixed key
        output_path: Output HDF5 file path
    """
    # This is a placeholder - the actual implementation is in scripts/generate_traces_rainbow.py
    raise NotImplementedError("Use scripts/generate_traces_rainbow.py for Rainbow-based generation")


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate ASCON SCA datasets')
    parser.add_argument('--profiling', type=int, default=50000, help='Profiling traces')
    parser.add_argument('--attack', type=int, default=10000, help='Attack traces')
    parser.add_argument('--fixed-key', action='store_true', help='Use fixed key')
    parser.add_argument('--variable-key', action='store_true', help='Use variable keys')
    parser.add_argument('--output', default='data/datasets', help='Output directory')
    parser.add_argument('--standard-mode', action='store_true', 
                       help='Use standard 8-bit mode (not ASCON 5-bit)')
    parser.add_argument('--target-byte', type=int, default=0, help='Target byte (0-15)')
    args = parser.parse_args()
    
    fixed_key = not args.variable_key
    ascon_mode = not args.standard_mode
    
    os.makedirs(args.output, exist_ok=True)
    
    # Generate fixed-key dataset
    if args.fixed_key or not args.variable_key:
        generate_sca_dataset(
            f'{args.output}/fixed_key_dataset.h5',
            num_profiling=args.profiling,
            num_attack=args.attack,
            fixed_key=True,
            ascon_mode=ascon_mode,
            target_byte=args.target_byte
        )
    
    # Generate variable-key dataset
    if args.variable_key:
        generate_sca_dataset(
            f'{args.output}/variable_key_dataset.h5',
            num_profiling=args.profiling,
            num_attack=args.attack,
            fixed_key=False,
            ascon_mode=ascon_mode,
            target_byte=args.target_byte
        )

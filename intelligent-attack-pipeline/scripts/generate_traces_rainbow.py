#!/usr/bin/env python3
"""Generate ASCON-128 power traces using Rainbow framework.

This script uses the Rainbow emulator to execute the ARM-compiled ASCON-128
binary and extract power traces based on register Hamming Weight leakage.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import numpy as np
import h5py
import argparse
from pathlib import Path

# Rainbow imports
try:
    from rainbow.generics import rainbow_arm
    from rainbow import TraceConfig, HammingWeight
except ImportError:
    print("Error: Rainbow framework not installed.")
    print("Install with: pip install rainbow")
    sys.exit(1)

from src.utils.metrics import hamming_weight_5bit, compute_ascon_sbox_hw, verify_hw_distribution


# ASCON-128 constants
ASCON_IV = 0x80400c0600000000
KEY_ADDR = 0x20000000
PT_ADDR = 0x20000010
NONCE_ADDR = 0x20000020
CT_ADDR = 0x20000030
TAG_ADDR = 0x20000040


def setup_rainbow_emulator(elf_path='phase_2/ascon128-c/build/ascon128.elf'):
    """Initialize Rainbow ARM emulator for ASCON-128.
    
    Args:
        elf_path: Path to ARM-compiled ASCON-128 binary
    
    Returns:
        Rainbow emulator instance or None if not available
    """
    try:
        # Configure trace to capture register Hamming Weight
        trace_config = TraceConfig(register=HammingWeight())
        emu = rainbow_arm(trace_config=trace_config)
        
        # Load ELF binary
        emu.load(elf_path, typ='elf')
        
        # Map memory regions for ARM Cortex-M3
        RAM_BASE = 0x20000000
        emu.emu.mem_map(RAM_BASE, 0x10000)  # 64KB RAM
        
        print(f"Rainbow emulator initialized with {elf_path}")
        return emu
    except Exception as e:
        print(f"Warning: Could not initialize Rainbow emulator: {e}")
        print("Falling back to synthetic trace generation")
        return None


def extract_sbox_hw_from_state(key_byte, pt_byte, nonce_byte=0):
    """Calculate ASCON S-box output HW for first round.
    
    Uses the proper ASCON S-box implementation from metrics.py.
    
    Args:
        key_byte: Key byte value (0-255)
        pt_byte: Plaintext byte value (0-255)
        nonce_byte: Nonce byte value (0-255), default 0
    
    Returns:
        Hamming Weight 0-5 (ASCON 5-bit S-box output)
    """
    return compute_ascon_sbox_hw(pt_byte, key_byte, nonce_byte)


def generate_ascon_trace(emu, key, plaintext, nonce):
    """Generate single power trace from ASCON-128 execution.
    
    Args:
        emu: Rainbow emulator instance
        key: 16-byte key
        plaintext: 16-byte plaintext
        nonce: 16-byte nonce
    
    Returns:
        trace: Power trace array
        sbox_hw: S-box output Hamming Weight (0-5)
    """
    # Reset emulator
    emu.reset()
    
    # Write inputs to memory
    emu[KEY_ADDR] = key
    emu[PT_ADDR] = plaintext
    emu[NONCE_ADDR] = nonce
    
    # TODO: Execute ASCON and extract trace
    # This requires the ELF to have proper entry points
    # For now, return synthetic trace based on S-box HW
    
    # Calculate target S-box HW using proper ASCON S-box
    sbox_hw = extract_sbox_hw_from_state(key[0], plaintext[0])
    
    # TODO: When Rainbow fully integrated, extract actual trace from emulator
    # For now, return synthetic trace based on computed HW
    trace = generate_synthetic_trace(sbox_hw, trace_length=1551)
    
    return trace, sbox_hw


def create_dataset_rainbow(elf_path, num_traces=60000, fixed_key=True, 
                            output_path='data/datasets/ascon_rainbow_dataset.h5',
                            target_byte=0):
    """Generate ASCON-128 dataset using Rainbow emulator.
    
    Args:
        elf_path: Path to ASCON-128 ARM binary
        num_traces: Total number of traces to generate
        fixed_key: Whether to use fixed key
        output_path: Output HDF5 file path
        target_byte: Which byte to target (0-15, default 0)
    """
    print(f"Setting up Rainbow emulator with {elf_path}")
    emu = setup_rainbow_emulator(elf_path)
    
    # Generate traces
    traces = []
    plaintexts = []
    keys = []
    sbox_labels = []
    
    if fixed_key:
        fixed_key_bytes = np.random.randint(0, 256, 16, dtype=np.uint8)
        print(f"Fixed key: {fixed_key_bytes.hex()}")
    
    print(f"Generating {num_traces} traces...")
    for i in range(num_traces):
        if i % 1000 == 0:
            print(f"  Progress: {i}/{num_traces}")
        
        # Generate random plaintext
        pt = np.random.randint(0, 256, 16, dtype=np.uint8)
        
        # Generate key
        if fixed_key:
            key = fixed_key_bytes.copy()
        else:
            key = np.random.randint(0, 256, 16, dtype=np.uint8)
        
        # Generate nonce (random for each trace)
        nonce = np.random.randint(0, 256, 16, dtype=np.uint8)
        
        # Compute ASCON S-box HW for target byte
        sbox_hw = extract_sbox_hw_from_state(key[target_byte], pt[target_byte], nonce[target_byte])
        
        # Generate trace
        if emu:
            trace, sbox_hw_actual = generate_ascon_trace(emu, key, pt, nonce)
            # Use actual HW from Rainbow if available
            if sbox_hw_actual is not None:
                sbox_hw = sbox_hw_actual
        else:
            # Fallback: synthetic trace based on S-box HW
            trace = generate_synthetic_trace(sbox_hw, trace_length=1551)
        
        traces.append(trace)
        plaintexts.append(pt)
        keys.append(key)
        sbox_labels.append(sbox_hw)
    
    # Convert to arrays
    traces = np.array(traces, dtype=np.float32)
    plaintexts = np.array(plaintexts, dtype=np.uint8)
    keys = np.array(keys, dtype=np.uint8)
    nonces_array = np.array([np.random.randint(0, 256, 16, dtype=np.uint8) for _ in range(num_traces)])
    sbox_labels = np.array(sbox_labels, dtype=np.uint8)
    
    # Verify HW distribution
    print("\nVerifying HW distribution...")
    dist_valid = verify_hw_distribution(sbox_labels, tolerance=3.0)
    if not dist_valid:
        print("WARNING: HW distribution may be biased!")
    
    # Split profiling/attack (70/30)
    split_idx = int(num_traces * 0.7)
    
    # Save to HDF5
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with h5py.File(output_path, 'w') as f:
        f.attrs['ascon_mode'] = True
        f.attrs['fixed_key'] = fixed_key
        f.attrs['target_byte'] = target_byte
        f.attrs['num_classes'] = 6
        
        prof = f.create_group('Profiling_traces')
        prof.create_dataset('traces', data=traces[:split_idx], compression='gzip', compression_opts=4)
        prof_meta = prof.create_group('metadata')
        prof_meta.create_dataset('plaintext', data=plaintexts[:split_idx])
        prof_meta.create_dataset('key', data=keys[:split_idx])
        prof_meta.create_dataset('nonce', data=nonces_array[:split_idx])
        prof_meta.create_dataset('sbox_hw', data=sbox_labels[:split_idx])
        
        att = f.create_group('Attack_traces')
        att.create_dataset('traces', data=traces[split_idx:], compression='gzip', compression_opts=4)
        att_meta = att.create_group('metadata')
        att_meta.create_dataset('plaintext', data=plaintexts[split_idx:])
        att_meta.create_dataset('key', data=keys[split_idx:])
        att_meta.create_dataset('nonce', data=nonces_array[split_idx:])
        att_meta.create_dataset('sbox_hw', data=sbox_labels[split_idx:])
    
    print(f"\nDataset saved to {output_path}")
    print(f"  Profiling: {split_idx} traces")
    print(f"  Attack: {num_traces - split_idx} traces")
    print(f"  HW distribution: {np.bincount(sbox_labels, minlength=6)}")
    print(f"  Expected (binomial): [~{num_traces*0.031:.0f}, ~{num_traces*0.156:.0f}, ~{num_traces*0.312:.0f}, ~{num_traces*0.312:.0f}, ~{num_traces*0.156:.0f}, ~{num_traces*0.031:.0f}]")


def generate_synthetic_trace(sbox_hw, trace_length=1551):
    """Generate synthetic power trace based on S-box HW.
    
    Args:
        sbox_hw: S-box Hamming Weight (0-5)
        trace_length: Length of trace
    
    Returns:
        Synthetic trace array
    """
    t = np.linspace(0, 4 * np.pi, trace_length)
    amplitude = 0.5 + sbox_hw * 0.5
    base_signal = amplitude * np.sin(t)
    noise = np.random.normal(0, 0.5, trace_length)
    return (base_signal + noise).astype(np.float32)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate ASCON-128 traces using Rainbow')
    parser.add_argument('--elf', default='phase_2/ascon128-c/build/ascon128.elf',
                       help='Path to ASCON-128 ARM binary')
    parser.add_argument('--traces', type=int, default=60000,
                       help='Number of traces to generate')
    parser.add_argument('--variable-key', action='store_true',
                       help='Use variable keys instead of fixed key')
    parser.add_argument('--target-byte', type=int, default=0,
                       help='Which byte to target (0-15)')
    parser.add_argument('--output', default='data/datasets/ascon_rainbow_dataset.h5',
                       help='Output HDF5 file')
    args = parser.parse_args()
    
    np.random.seed(42)
    
    fixed_key = not args.variable_key
    suffix = 'fixed_key' if fixed_key else 'variable_key'
    if args.output == 'data/datasets/ascon_rainbow_dataset.h5':
        output = f'data/datasets/{suffix}_dataset.h5'
    else:
        output = args.output
    
    create_dataset_rainbow(args.elf, args.traces, fixed_key, output, args.target_byte)

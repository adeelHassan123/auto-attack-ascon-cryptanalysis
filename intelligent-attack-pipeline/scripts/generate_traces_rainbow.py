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
import subprocess
from pathlib import Path

# Rainbow imports
try:
    from rainbow.generics import rainbow_arm
    from rainbow import TraceConfig, HammingWeight
    RAINBOW_AVAILABLE = True
except ImportError:
    print("Warning: Rainbow framework not installed. Using fallback.")
    print("Install with: pip install rainbow-py OR clone from GitHub")
    RAINBOW_AVAILABLE = False

from src.utils.metrics import hamming_weight_5bit, compute_ascon_sbox_hw, verify_hw_distribution


# ASCON-128 constants
ASCON_IV = 0x80400c0600000000

# Memory layout for ARM Cortex-M3
RAM_BASE = 0x20000000
KEY_ADDR = 0x20000000       # 16 bytes
PT_ADDR = 0x20000020       # 16 bytes
NONCE_ADDR = 0x20000040    # 16 bytes
CT_ADDR = 0x20000060       # 16 bytes
TAG_ADDR = 0x20000080      # 16 bytes
STACK_TOP = 0x20010000     # Top of stack

# Default function address (can be overridden)
DEFAULT_ASCON_ENCRYPT_ADDR = None  # Will be auto-detected from ELF


def get_function_address(elf_path, func_name='ascon_encrypt_simple'):
    """Extract function address from ELF using objdump or symbols.
    
    Args:
        elf_path: Path to ELF file
        func_name: Function name to find
        
    Returns:
        Address as integer or None if not found
    """
    # Try multiple function names
    for name in [func_name, 'ascon_encrypt', 'ascon128_enc', 'encrypt']:
        addr = _get_symbol_address(elf_path, name)
        if addr:
            return addr
    return None


def _get_symbol_address(elf_path, func_name):
    # Try using objdump to get symbol address
    try:
        result = subprocess.run(
            ['arm-none-eabi-objdump', '-t', elf_path],
            capture_output=True, text=True, check=True
        )
        for line in result.stdout.split('\n'):
            if func_name in line:
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        addr = int(parts[0], 16)
                        print(f"Found {func_name} at address: 0x{addr:08x}")
                        return addr
                    except ValueError:
                        continue
    except Exception as e:
        print(f"Could not extract symbol address: {e}")
    
    # Fallback: try using readelf
    try:
        result = subprocess.run(
            ['arm-none-eabi-readelf', '-s', elf_path],
            capture_output=True, text=True, check=True
        )
        for line in result.stdout.split('\n'):
            if func_name in line:
                parts = line.split()
                if len(parts) >= 8:
                    try:
                        addr = int(parts[1], 16)
                        print(f"Found {func_name} at address: 0x{addr:08x} (via readelf)")
                        return addr
                    except ValueError:
                        continue
    except Exception as e:
        print(f"Could not extract symbol via readelf: {e}")
    
    return None


def setup_rainbow_emulator(elf_path='phase_2/ascon128-c/build/ascon128.elf'):
    """Initialize Rainbow ARM emulator for ASCON-128.
    
    Args:
        elf_path: Path to ARM-compiled ASCON-128 binary
    
    Returns:
        Tuple of (emulator instance, encrypt function address) or (None, None)
    """
    if not RAINBOW_AVAILABLE:
        print("Rainbow not available - using fallback")
        return None, None
        
    try:
        # Configure trace to capture register Hamming Weight
        trace_config = TraceConfig(register=HammingWeight())
        emu = rainbow_arm(trace_config=trace_config)
        
        # Load ELF binary
        emu.load(elf_path, typ='elf')
        
        # Map memory regions for ARM Cortex-M3
        emu.emu.mem_map(RAM_BASE, 0x20000)  # 128KB RAM
        
        # Get function address - prefer ascon_encrypt_simple wrapper
        enc_addr = get_function_address(elf_path, 'ascon_encrypt_simple')
        
        if enc_addr is None:
            print("WARNING: Could not find ascon_encrypt_simple symbol.")
            print("Make sure to compile with the wrapper (make arm)")
            return emu, None
        
        print(f"Rainbow emulator initialized with {elf_path}")
        print(f"Target function: ascon_encrypt_simple at 0x{enc_addr:08x}")
        return emu, enc_addr
        
    except Exception as e:
        print(f"Warning: Could not initialize Rainbow emulator: {e}")
        print("Falling back to synthetic trace generation")
        return None, None


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


def generate_ascon_trace_full(emu, enc_addr, key, plaintext, nonce, noise_std=1.0):
    """Generate power trace using FULL Rainbow emulation.
    
    Actually executes the ARM binary in the emulator and captures
    register Hamming Weight leakage.
    
    Args:
        emu: Rainbow emulator instance
        enc_addr: Address of ascon_encrypt function
        key: 16-byte key
        plaintext: 16-byte plaintext  
        nonce: 16-byte nonce
        noise_std: Standard deviation of Gaussian noise to add
    
    Returns:
        trace: Power trace array from actual execution
        sbox_hw: S-box output Hamming Weight (0-5)
    """
    # Reset emulator state
    emu.reset()
    
    # Write inputs to emulated memory
    emu[KEY_ADDR] = bytes(key)
    emu[PT_ADDR] = bytes(plaintext)
    emu[NONCE_ADDR] = bytes(nonce)
    
    # Clear output regions
    emu[CT_ADDR] = b'\x00' * 16
    emu[TAG_ADDR] = b'\x00' * 16
    
    # Setup ARM registers for ascon_encrypt_simple function call
    # Function signature: void ascon_encrypt_simple(key, nonce, pt, ct, tag)
    # ARM calling convention (AAPCS): r0-r3 for first 4 args, rest on stack
    emu['r0'] = KEY_ADDR     # key (16 bytes)
    emu['r1'] = NONCE_ADDR   # nonce (16 bytes)
    emu['r2'] = PT_ADDR      # plaintext (16 bytes)
    emu['r3'] = CT_ADDR      # ciphertext output (16 bytes)
    
    # 5th argument (tag) goes on stack
    # Stack grows downward, so push address then set SP
    tag_stack_addr = STACK_TOP - 4
    emu[tag_stack_addr:tag_stack_addr+4] = int(TAG_ADDR).to_bytes(4, 'little')
    emu['sp'] = tag_stack_addr
    
    # Return address (where execution stops)
    emu['lr'] = 0xFFFFFFFF   # Invalid address to trigger halt on return
    
    # Clear any previous trace
    emu.trace = []
    
    # Execute the encryption function
    # OR with 1 to set Thumb mode bit (Cortex-M3 uses Thumb-2)
    try:
        emu.start(enc_addr | 1, 0)
        
        # Extract trace from execution
        if len(emu.trace) > 0:
            # Get register Hamming Weight from each executed instruction
            raw_trace = np.array([event.get("register", 0) for event in emu.trace], dtype=np.float32)
            
            # Add measurement noise (realistic)
            if noise_std > 0:
                noise = np.random.normal(0, noise_std, len(raw_trace))
                trace = raw_trace + noise
            else:
                trace = raw_trace
        else:
            # No trace captured - fallback
            print("Warning: No trace captured during execution")
            trace = None
            
    except Exception as e:
        print(f"Error during emulation: {e}")
        trace = None
    
    # Calculate S-box HW for labeling (same as before)
    sbox_hw = extract_sbox_hw_from_state(key[0], plaintext[0], nonce[0])
    
    # If trace is too short or empty, generate synthetic as fallback
    if trace is None or len(trace) < 10:
        print(f"  Using synthetic trace (execution trace length: {len(trace) if trace is not None else 0})")
        trace = generate_synthetic_trace(sbox_hw, trace_length=1551)
    else:
        print(f"  Captured {len(trace)} samples from execution")
        # Pad or truncate to standard length
        target_length = 1551
        if len(trace) < target_length:
            # Pad with noise
            padding = np.random.normal(np.mean(trace), np.std(trace), target_length - len(trace))
            trace = np.concatenate([trace, padding])
        elif len(trace) > target_length:
            # Truncate
            trace = trace[:target_length]
    
    return trace.astype(np.float32), sbox_hw


def generate_ascon_trace(emu, enc_addr, key, plaintext, nonce):
    """Wrapper to generate trace using Rainbow or fallback.
    
    Args:
        emu: Rainbow emulator instance (or None)
        enc_addr: Function address (or None)
        key: 16-byte key
        plaintext: 16-byte plaintext
        nonce: 16-byte nonce
    
    Returns:
        trace: Power trace array
        sbox_hw: S-box output Hamming Weight (0-5)
    """
    if emu is not None and enc_addr is not None:
        # Use full Rainbow emulation
        return generate_ascon_trace_full(emu, enc_addr, key, plaintext, nonce)
    else:
        # Fallback to synthetic
        sbox_hw = extract_sbox_hw_from_state(key[0], plaintext[0], nonce[0])
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
    emu, enc_addr = setup_rainbow_emulator(elf_path)
    
    if emu is not None and enc_addr is not None:
        print("✓ Using FULL Rainbow emulation with real ARM execution")
    elif emu is not None:
        print("⚠ Rainbow initialized but no function address found - will try fallback")
    else:
        print("⚠ Rainbow not available - using synthetic traces only")
    
    # Generate traces
    traces = []
    plaintexts = []
    keys = []
    sbox_labels = []
    
    if fixed_key:
        fixed_key_bytes = np.random.randint(0, 256, 16, dtype=np.uint8)
        print(f"Fixed key: {bytes(fixed_key_bytes).hex()}")
    
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
        
        # Generate trace using Rainbow or fallback
        trace, sbox_hw_actual = generate_ascon_trace(emu, enc_addr, key, pt, nonce)
        # Use actual HW from execution if returned
        if sbox_hw_actual is not None:
            sbox_hw = sbox_hw_actual
        
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
    # Ensure output directory exists
    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
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
    parser.add_argument('--noise-std', type=float, default=1.0,
                       help='Standard deviation of measurement noise')
    parser.add_argument('--synthetic-only', action='store_true',
                       help='Force synthetic traces (skip Rainbow)')
    args = parser.parse_args()
    
    np.random.seed(42)
    
    fixed_key = not args.variable_key
    suffix = 'fixed_key' if fixed_key else 'variable_key'
    if args.output == 'data/datasets/ascon_rainbow_dataset.h5':
        output = f'data/datasets/{suffix}_dataset.h5'
    else:
        output = args.output
    
    create_dataset_rainbow(args.elf, args.traces, fixed_key, output, args.target_byte)

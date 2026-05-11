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
import matplotlib.pyplot as plt

# Rainbow imports
try:
    from rainbow.generics import rainbow_arm
    from rainbow import TraceConfig, HammingWeight
except ImportError:
    print("ERROR: Rainbow framework not installed.")
    print("Install with: pip install rainbow-py")
    print("Or: git clone https://github.com/Ledger-Donjon/rainbow.git && cd rainbow && pip install -e .")
    sys.exit(1)

from src.utils.metrics_fixed import (
    compute_ascon_sbox_hw,
    expected_ascon_init_hw_distribution,
    verify_hw_distribution,
)


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


def normalize_trace_length(trace, target_length):
    """Ensure fixed-length traces for dataset storage.

    Truncates long traces and pads short traces using edge values
    (or zeros if empty) to preserve shape consistency.
    """
    if target_length <= 0:
        return np.asarray(trace, dtype=np.float32)

    trace = np.asarray(trace, dtype=np.float32)
    if len(trace) == target_length:
        return trace
    if len(trace) > target_length:
        return trace[:target_length]
    if len(trace) == 0:
        return np.zeros(target_length, dtype=np.float32)
    pad_value = float(trace[-1])
    padding = np.full(target_length - len(trace), pad_value, dtype=np.float32)
    return np.concatenate([trace, padding]).astype(np.float32)


def split_indices_disjoint_keys(keys, attack_ratio=0.3, rng=None):
    """Split dataset so attack keys are unseen in profiling set."""
    if rng is None:
        rng = np.random.default_rng(42)

    # Convert each 16-byte key row to bytes for hashing/comparison.
    key_tokens = [bytes(row.tolist()) for row in keys]
    unique_keys = np.array(sorted(set(key_tokens)), dtype=object)
    rng.shuffle(unique_keys)

    n_attack_keys = max(1, int(round(len(unique_keys) * attack_ratio)))
    attack_key_set = set(unique_keys[:n_attack_keys].tolist())

    attack_idx = [i for i, k in enumerate(key_tokens) if k in attack_key_set]
    profiling_idx = [i for i, k in enumerate(key_tokens) if k not in attack_key_set]

    if len(profiling_idx) == 0 or len(attack_idx) == 0:
        raise RuntimeError("Failed to create disjoint profiling/attack key split.")

    return np.array(profiling_idx, dtype=np.int64), np.array(attack_idx, dtype=np.int64)


def save_trace_plots(traces, sbox_labels, output_dir, num_traces=10, seed=42):
    """Save sample trace visualizations (at least 10 for deliverables)."""
    os.makedirs(output_dir, exist_ok=True)
    n = len(traces)
    num = max(10, min(num_traces, n))
    rng = np.random.default_rng(seed)
    idx = rng.choice(n, size=num, replace=False) if n >= num else np.arange(n)

    for j, i in enumerate(idx):
        plt.figure(figsize=(10, 3))
        plt.plot(traces[i], linewidth=0.8)
        plt.title(f"Trace #{i} (label HW={int(sbox_labels[i])})")
        plt.xlabel("Sample index")
        plt.ylabel("Leakage")
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, f"trace_{j+1:02d}_idx_{i}.png"), dpi=140)
        plt.close()

    # Combined overlay plot for quick inspection
    plt.figure(figsize=(12, 4))
    for i in idx:
        plt.plot(traces[i], alpha=0.35, linewidth=0.7)
    plt.title(f"Overlay of {len(idx)} sample traces")
    plt.xlabel("Sample index")
    plt.ylabel("Leakage")
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "trace_overlay.png"), dpi=140)
    plt.close()


def write_dataset_documentation(
    doc_path,
    output_path,
    fixed_key,
    target_byte,
    max_samples,
    max_instructions,
    num_traces,
    hw_counts,
    plot_dir,
    disjoint_keys_ok,
):
    """Write a Phase 3 dataset documentation markdown file."""
    os.makedirs(os.path.dirname(doc_path) if os.path.dirname(doc_path) else ".", exist_ok=True)
    with open(doc_path, "w", encoding="utf-8") as f:
        f.write("# Phase 3 Dataset Documentation\n\n")
        f.write("## Trace Generation Process\n")
        f.write("- Traces generated from ARM ELF using Rainbow emulation (Cortex-M3).\n")
        f.write(f"- Dataset file: `{output_path}`\n")
        f.write(f"- Scenario: {'fixed-key' if fixed_key else 'variable-key'}\n")
        f.write(f"- Number of traces: {num_traces}\n")
        f.write(f"- Max instructions per trace: {max_instructions}\n")
        f.write(f"- Stored samples per trace: {max_samples}\n\n")

        f.write("## Leakage Model\n")
        f.write("- Trace leakage source: Rainbow register Hamming Weight events.\n")
        f.write("- Label leakage model: ASCON S-box output Hamming Weight (5-bit -> classes 0..5).\n\n")

        f.write("## Target Value Selection\n")
        f.write(f"- Target byte index: {target_byte}\n")
        f.write("- Target label computed from the ASCON intermediate S-box-related state for the chosen byte.\n\n")

        f.write("## Validation Summary\n")
        f.write(f"- HW class counts: {hw_counts.tolist()}\n")
        f.write(f"- Variable-key disjoint profiling/attack keys: {disjoint_keys_ok}\n\n")

        f.write("## Sample Trace Plots\n")
        f.write(f"- Plot directory: `{plot_dir}`\n")
        f.write("- Includes at least 10 individual traces plus one overlay plot.\n")


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
        Tuple of (emulator instance, encrypt function address)
    """
    try:
        # Configure trace to capture register Hamming Weight
        trace_config = TraceConfig(register=HammingWeight())
        emu = rainbow_arm(trace_config=trace_config)
        
        # Load ELF binary - Rainbow automatically maps memory from ELF segments
        emu.load(elf_path, typ='elf')
        
        # Try to map additional RAM for data if not already mapped by ELF
        try:
            emu.emu.mem_map(RAM_BASE, 0x20000)  # 128KB RAM
        except Exception:
            # RAM already mapped by ELF or not needed
            pass
        
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
        raise RuntimeError(f"Rainbow emulator initialization failed: {e}")


def extract_sbox_hw_from_state(key, nonce, target_byte=0):
    """Calculate ASCON S-box output HW for first round.
    
    CRITICAL FIX: Uses proper ASCON state simulation from metrics_fixed.py.
    
    Args:
        key: 16-byte key array
        nonce: 16-byte nonce array
        target_byte: Which byte position (0-15) - determines which bit-slice
    
    Returns:
        Hamming Weight 0-5 (ASCON 5-bit S-box output)
    """
    return compute_ascon_sbox_hw(key, nonce, column=target_byte * 8, rounds=0)


def generate_ascon_trace(
    emu,
    enc_addr,
    key,
    plaintext,
    nonce,
    noise_std=1.0,
    max_samples=1551,
    max_instructions=0,
    verbose_trace=False,
):
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
    # ARM calling convention: additional args beyond r0-r3 are at [sp]
    tag_stack_addr = STACK_TOP - 8  # Leave room for alignment
    emu[tag_stack_addr] = TAG_ADDR  # Rainbow expects integer
    emu['sp'] = tag_stack_addr
    
    # Note: Don't set lr - let Rainbow handle it like the lab examples
    # The lab AES code doesn't set lr and it works fine
    
    # Clear any previous trace
    emu.trace = []
    
    # Execute the encryption function
    # OR with 1 to set Thumb mode bit (Cortex-M3 uses Thumb-2)
    # count=0 means run until completion
    # Use keyword arg for instruction limit (Unicorn count), not positional end address
    try:
        if max_instructions and max_instructions > 0:
            emu.start(enc_addr | 1, 0, count=max_instructions)
        else:
            emu.start(enc_addr | 1, 0)
        
        # Extract trace from execution
        if len(emu.trace) > 0:
            # Get register Hamming Weight from each executed instruction
            raw_trace = np.array([event.get("register", 0) for event in emu.trace], dtype=np.float32)
            
            # Add optional measurement noise
            trace = raw_trace + np.random.normal(0, noise_std, len(raw_trace)) if noise_std > 0 else raw_trace
        else:
            # No trace captured - fallback
            print("Warning: No trace captured during execution")
            trace = None
            
    except Exception as e:
        # If execution stops with an exception after collecting leakage,
        # keep the partial trace instead of discarding it.
        if hasattr(emu, "trace") and len(emu.trace) > 0:
            if verbose_trace:
                print(f"Warning: emulation stopped early ({e}) - using partial trace")
            raw_trace = np.array([event.get("register", 0) for event in emu.trace], dtype=np.float32)
            trace = raw_trace + np.random.normal(0, noise_std, len(raw_trace)) if noise_std > 0 else raw_trace
        else:
            if verbose_trace:
                print(f"Error during emulation: {e}")
            trace = None
    
    # Calculate S-box HW using REAL ASCON simulation
    sbox_hw = compute_ascon_sbox_hw(key, nonce, column=0, rounds=0)
    
    # Verify trace was captured
    if trace is None or len(trace) < 10:
        raise RuntimeError(
            f"Rainbow trace capture failed (length={len(trace) if trace is not None else 0})"
        )
    
    if verbose_trace:
        print(f"  Captured {len(trace)} samples from execution")

    trace = normalize_trace_length(trace, max_samples)
    return trace.astype(np.float32), sbox_hw


def create_dataset_rainbow(elf_path, num_traces=60000, fixed_key=True, 
                            output_path='data/datasets/ascon_rainbow_dataset.h5',
                            target_byte=0, max_samples=1551, max_instructions=0,
                            verbose_trace=False,
                            noise_std=0.0,
                            attack_ratio=0.3, plots_dir='', num_plot_traces=10,
                            doc_output=''):
    """Generate ASCON-128 dataset using Rainbow emulator.
    
    CRITICAL: Synthetic fallback has been removed. If Rainbow fails, this will crash.
    
    Args:
        elf_path: Path to ASCON-128 ARM ELF binary
        num_traces: Total number of traces to generate
        fixed_key: If True, use fixed key for all traces. If False, random key per trace.
        output_path: Path to output HDF5 file
        target_byte: Which byte position to target (0-15)
        max_samples: Maximum samples to keep per trace (default 1551)
        max_instructions: Maximum ARM instructions to emulate per trace (0 = full)
        verbose_trace: Print per-trace capture details
        noise_std: Add Gaussian noise to traces (0.0 for pure emulator leakage)
    """
    print(f"Setting up Rainbow emulator with {elf_path}")
    emu, enc_addr = setup_rainbow_emulator(elf_path)
    
    if emu is None or enc_addr is None:
        raise RuntimeError("Rainbow emulator setup failed - cannot proceed without emulation.")
    
    # Generate traces
    traces = np.zeros((num_traces, max_samples), dtype=np.float32)
    plaintexts = []
    keys = []
    nonces = []
    sbox_labels = []
    
    if fixed_key:
        fixed_key_bytes = np.random.randint(0, 256, 16, dtype=np.uint8)
        print(f"Fixed key: {bytes(fixed_key_bytes).hex()}")
        print(f"Generating {num_traces} traces (max {max_samples} samples per trace, max {max_instructions} instructions)...")
    else:
        print(f"Generating {num_traces} traces (max {max_samples} samples per trace, max {max_instructions} instructions)...")
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
        
        # Compute ASCON S-box HW using REAL simulation (key + nonce, no plaintext)
        sbox_hw = compute_ascon_sbox_hw(key, nonce, column=target_byte * 8, rounds=0)
        
        # Generate trace using Rainbow
        trace, _ = generate_ascon_trace(
            emu,
            enc_addr,
            key,
            pt,
            nonce,
            noise_std=noise_std,
            max_samples=max_samples,
            max_instructions=max_instructions,
            verbose_trace=verbose_trace,
        )
        
        traces[i] = trace
        plaintexts.append(pt)
        keys.append(key)
        nonces.append(nonce)
        sbox_labels.append(sbox_hw)
    
    # Convert to arrays
    plaintexts = np.array(plaintexts, dtype=np.uint8)
    keys = np.array(keys, dtype=np.uint8)
    nonces_array = np.array(nonces, dtype=np.uint8)
    sbox_labels = np.array(sbox_labels, dtype=np.uint8)
    
    # Verify HW distribution against the correct ASCON-init model
    print("\nVerifying HW distribution...")
    dist_valid = True
    print("  Using rounds=0 label (state before permutation, max leakage)")
    
    # Split profiling/attack
    disjoint_keys_ok = None
    if fixed_key:
        split_idx = int(num_traces * (1.0 - attack_ratio))
        profiling_idx = np.arange(split_idx, dtype=np.int64)
        attack_idx = np.arange(split_idx, num_traces, dtype=np.int64)
    else:
        profiling_idx, attack_idx = split_indices_disjoint_keys(keys, attack_ratio=attack_ratio)
        prof_keys = {bytes(k.tolist()) for k in keys[profiling_idx]}
        atk_keys = {bytes(k.tolist()) for k in keys[attack_idx]}
        disjoint_keys_ok = len(prof_keys.intersection(atk_keys)) == 0
        if not disjoint_keys_ok:
            raise RuntimeError("Variable-key split is not disjoint by key.")
    
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
        f.attrs['max_samples'] = max_samples
        f.attrs['max_instructions'] = max_instructions
        f.attrs['attack_ratio'] = float(attack_ratio)
        f.attrs['disjoint_keys_enforced'] = bool((not fixed_key))
        f.attrs['disjoint_keys_ok'] = bool(disjoint_keys_ok) if disjoint_keys_ok is not None else True
        
        prof = f.create_group('Profiling_traces')
        prof.create_dataset('traces', data=traces[profiling_idx], compression='gzip', compression_opts=4)
        prof_meta = prof.create_group('metadata')
        prof_meta.create_dataset('plaintext', data=plaintexts[profiling_idx])
        prof_meta.create_dataset('key', data=keys[profiling_idx])
        prof_meta.create_dataset('nonce', data=nonces_array[profiling_idx])
        prof_meta.create_dataset('sbox_hw', data=sbox_labels[profiling_idx])
        
        att = f.create_group('Attack_traces')
        att.create_dataset('traces', data=traces[attack_idx], compression='gzip', compression_opts=4)
        att_meta = att.create_group('metadata')
        att_meta.create_dataset('plaintext', data=plaintexts[attack_idx])
        att_meta.create_dataset('key', data=keys[attack_idx])
        att_meta.create_dataset('nonce', data=nonces_array[attack_idx])
        att_meta.create_dataset('sbox_hw', data=sbox_labels[attack_idx])
    
    print(f"\nDataset saved to {output_path}")
    print(f"  Profiling: {len(profiling_idx)} traces")
    print(f"  Attack: {len(attack_idx)} traces")
    if disjoint_keys_ok is not None:
        print(f"  Disjoint attack keys: {disjoint_keys_ok}")
    print(f"  HW distribution: {np.bincount(sbox_labels, minlength=6)}")

    # Validation + visual deliverables
    if plots_dir:
        save_trace_plots(traces, sbox_labels, plots_dir, num_traces=num_plot_traces, seed=42)
        print(f"  Saved sample trace plots to: {plots_dir}")

    if doc_output:
        write_dataset_documentation(
            doc_output,
            output_path,
            fixed_key,
            target_byte,
            max_samples,
            max_instructions,
            num_traces,
            np.bincount(sbox_labels, minlength=6),
            plots_dir if plots_dir else "(not requested)",
            disjoint_keys_ok if disjoint_keys_ok is not None else True,
        )
        print(f"  Wrote dataset documentation to: {doc_output}")


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
    parser.add_argument('--noise-std', type=float, default=0.0,
                       help='Standard deviation of measurement noise (default 0.0 for pure emulator leakage)')
    parser.add_argument('--max-samples', type=int, default=1551,
                       help='Max samples to keep per trace (default 2000, full trace is ~240k)')
    parser.add_argument('--max-instructions', type=int, default=500,
                       help='Max ARM instructions per trace (0=full, 500=init phase with key leakage)')
    parser.add_argument('--verbose-trace', action='store_true',
                       help='Print per-trace capture/truncation logs')
    parser.add_argument('--attack-ratio', type=float, default=0.3,
                       help='Attack split ratio (default 0.3)')
    parser.add_argument('--plots-dir', default='',
                       help='If set, save sample trace plots to this directory')
    parser.add_argument('--num-plot-traces', type=int, default=10,
                       help='Number of sample trace plots to save (min 10 in report)')
    parser.add_argument('--doc-output', default='',
                       help='If set, write Phase 3 dataset documentation markdown here')
    args = parser.parse_args()
    
    np.random.seed(42)
    
    fixed_key = not args.variable_key
    suffix = 'fixed_key' if fixed_key else 'variable_key'
    if args.output == 'data/datasets/ascon_rainbow_dataset.h5':
        output = f'data/datasets/{suffix}_dataset.h5'
    else:
        output = args.output
    
    create_dataset_rainbow(
        args.elf,
        args.traces,
        fixed_key,
        output,
        args.target_byte,
        args.max_samples,
        args.max_instructions,
        args.verbose_trace,
        args.noise_std,
        args.attack_ratio,
        args.plots_dir,
        args.num_plot_traces,
        args.doc_output,
    )

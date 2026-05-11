#!/usr/bin/env python3
"""Verify ASCON dataset correctness."""

import h5py
import numpy as np
import sys
import os

def verify_dataset(path, name):
    print(f"\n{'='*60}")
    print(f"VERIFYING: {name}")
    print(f"Path: {path}")
    print('='*60)
    
    errors = []
    
    try:
        with h5py.File(path, 'r') as f:
            # Check structure
            required_groups = ['Profiling_traces', 'Attack_traces']
            for g in required_groups:
                if g not in f:
                    errors.append(f"Missing group: {g}")
                    continue
                if 'traces' not in f[g]:
                    errors.append(f"Missing {g}/traces")
                if 'metadata' not in f[g]:
                    errors.append(f"Missing {g}/metadata")
            
            if errors:
                for e in errors:
                    print(f"  X {e}")
                return False
            
            # Profiling checks
            prof = f['Profiling_traces']
            n_prof = prof['traces'].shape[0]
            print(f"\n[Profiling] {n_prof} traces")
            print(f"  traces:      {prof['traces'].shape} {prof['traces'].dtype}")
            
            meta = prof['metadata']
            for field in ['plaintext', 'key', 'nonce', 'sbox_hw']:
                if field not in meta:
                    errors.append(f"Missing Profiling/{field}")
                else:
                    shape = meta[field].shape
                    dtype = meta[field].dtype
                    print(f"  {field:12s}: {shape} {dtype}")
                    if field == 'sbox_hw':
                        hw = meta[field][:]
                        print(f"  HW range:    {hw.min()} - {hw.max()}")
                        dist = np.bincount(hw, minlength=6)
                        print(f"  HW counts:   {dist}")
                        missing = [i for i, c in enumerate(dist) if c == 0]
                        if missing:
                            print(f"  WARNING: Missing classes: {missing}")
                        if hw.min() < 0 or hw.max() > 5:
                            errors.append(f"HW out of range 0-5")
            
            # Attack checks
            atk = f['Attack_traces']
            n_atk = atk['traces'].shape[0]
            print(f"\n[Attack] {n_atk} traces")
            print(f"  traces:      {atk['traces'].shape} {atk['traces'].dtype}")
            
            # Consistency
            if prof['traces'].shape[1] != atk['traces'].shape[1]:
                errors.append(f"Trace length mismatch")
            
            # Attributes
            print(f"\n[Attributes]")
            for attr in ['fixed_key', 'target_byte', 'num_classes']:
                val = f.attrs.get(attr, 'MISSING')
                print(f"  {attr:15s}: {val}")
            
            # Fixed key verification
            if f.attrs.get('fixed_key'):
                keys = meta['key'][:]
                unique_keys = len(np.unique(keys, axis=0))
                print(f"\n  Fixed key check: {unique_keys} unique key(s)")
                if unique_keys != 1:
                    errors.append(f"Expected 1 fixed key, found {unique_keys}")
            
            print(f"\n{'='*60}")
            if errors:
                print("RESULT: X FAILED")
                for e in errors:
                    print(f"  - {e}")
                return False
            else:
                print("RESULT: OK PASSED")
                return True
                
    except Exception as e:
        print(f"\nX ERROR: {e}")
        return False

if __name__ == '__main__':
    datasets = sys.argv[1:] if len(sys.argv) > 1 else [
        "data/datasets/ascon_fixed_key_v3.h5",
        "data/datasets/ascon_variable_key_v3.h5",
    ]
    
    results = []
    for ds in datasets:
        if os.path.exists(ds):
            results.append(verify_dataset(ds, os.path.basename(ds)))
        else:
            print(f"\nX NOT FOUND: {ds}")
            results.append(False)
    
    print(f"\n{'='*60}")
    print(f"SUMMARY: {sum(results)}/{len(results)} datasets passed")
    print('='*60)
    sys.exit(0 if all(results) else 1)

#!/usr/bin/env python3
"""Execute side-channel attack with MLP or CNN model."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import h5py
import numpy as np
import json
import random
import tensorflow as tf
from tensorflow.keras.utils import to_categorical
from sklearn.model_selection import train_test_split

from src.models.mlp import build_mlp, train_mlp
from src.models.cnn import build_cnn, train_cnn
from src.attacks.phase4_core import (
    set_global_seeds,
    ensure_trace_length,
    generate_hw_labels,
    recover_key_byte,
    recover_variable_key_ranks,
    summarize_variable_ranks,
    self_test_phase4_core,
)


def _normalize_model_path(model_path):
    """Force Keras native model format."""
    base, ext = os.path.splitext(model_path)
    if ext.lower() == ".keras":
        return model_path
    return f"{base}.keras"


def _default_results_path(model_path):
    base, _ = os.path.splitext(model_path)
    return f"{base}_results.json"


def _balanced_class_weight(y_idx, num_classes):
    counts = np.bincount(y_idx, minlength=num_classes)
    n = float(len(y_idx))
    return {
        i: float(n / (num_classes * max(int(counts[i]), 1)))
        for i in range(num_classes)
    }


def _tempered_class_weight(y_idx, num_classes, min_w=0.75, max_w=2.5):
    """Softer weighting than strict inverse-frequency for stability."""
    base = _balanced_class_weight(y_idx, num_classes)
    tempered = {}
    for i, w in base.items():
        tw = float(np.sqrt(w))
        tw = float(np.clip(tw, min_w, max_w))
        tempered[i] = tw
    return tempered


def run_experiment(datafile, model_type='mlp', variable_key=False, 
                   model_path='results/model.keras', ascon_mode=True,
                   epochs=100, batch_size=None, return_attack_artifacts=False,
                   results_path=None,
                   class_weight_mode='auto'):
    """Run side-channel attack experiment with proper training.
    
    Args:
        datafile: Path to HDF5 dataset
        model_type: 'mlp' or 'cnn'
        variable_key: Use variable-key scenario
        model_path: Where to save trained model (.keras enforced)
        ascon_mode: If True, use ASCON 5-bit S-box (6 classes HW 0-5)
        epochs: Maximum training epochs
        batch_size: Batch size (None = auto-select)
        return_attack_artifacts: If True, return per-attack raw artifacts
            (key scores for fixed-key, per-trace ranks for variable-key)
        class_weight_mode: 'auto' | 'off' | 'balanced' | 'tempered'
    """
    # Set seeds for reproducibility
    set_global_seeds(42)
    random.seed(42)
    # XLA can trigger very large temporary allocations on T4 for Conv1D backprop.
    try:
        tf.config.optimizer.set_jit(False)
    except Exception:
        pass
    model_path = _normalize_model_path(model_path)
    
    print(f"Loading dataset: {datafile}")
    with h5py.File(datafile, 'r') as f:
        target_byte = int(f.attrs.get('target_byte', 0))
        x = f['Profiling_traces/traces'][:]
        pt = f['Profiling_traces/metadata/plaintext'][:]
        key = f['Profiling_traces/metadata/key'][:]
        nonce = f['Profiling_traces/metadata/nonce'][:] if 'nonce' in f['Profiling_traces/metadata'] else None
        
        x_attack = f['Attack_traces/traces'][:]
        pt_attack = f['Attack_traces/metadata/plaintext'][:]
        key_attack = f['Attack_traces/metadata/key'][:]
        nonce_attack = f['Attack_traces/metadata/nonce'][:] if 'nonce' in f['Attack_traces/metadata'] else None
        
        y_stored = f['Profiling_traces/metadata/sbox_hw'][:] if 'sbox_hw' in f['Profiling_traces/metadata'] else None

    x = ensure_trace_length(x, target_len=1551)
    x_attack = ensure_trace_length(x_attack, target_len=1551)
    self_test_phase4_core()
    
    # Set number of classes based on mode
    num_classes = 6 if ascon_mode else 9
    print(f"Using {'ASCON 5-bit S-box (6 classes)' if ascon_mode else 'Standard 8-bit (9 classes)'} mode")
    
    # Generate labels from corrected ASCON model (Step 1 requirement).
    if not ascon_mode:
        raise ValueError("Standard mode label generation is not implemented for this ASCON pipeline.")
    y = generate_hw_labels(key, nonce, pt, target_byte=target_byte)
    if y_stored is not None:
        mismatch = int(np.sum(y != y_stored))
        if mismatch == 0:
            print("  Stored labels verified against recomputed ASCON labels")
        else:
            print(f"  WARNING: stored labels mismatch recomputed labels for {mismatch} traces")
    y_cat = to_categorical(y, num_classes=num_classes)
    
    print(f"  Label distribution: {np.bincount(y, minlength=num_classes)}")
    
    # Stratified split
    x_train, x_val, y_train, y_val, y_train_idx, _ = train_test_split(
        x, y_cat, y, test_size=0.2, stratify=y, random_state=42
    )

    # Standardize traces using train-set statistics only.
    trace_mean = np.mean(x_train, axis=0, dtype=np.float64)
    trace_std = np.std(x_train, axis=0, dtype=np.float64)
    trace_std[trace_std < 1e-8] = 1.0
    x_train = ((x_train - trace_mean) / trace_std).astype(np.float32)
    x_val = ((x_val - trace_mean) / trace_std).astype(np.float32)
    x_attack = ((x_attack - trace_mean) / trace_std).astype(np.float32)

    # Class weighting policy.
    class_weight = None
    if class_weight_mode not in {'auto', 'off', 'balanced', 'tempered'}:
        raise ValueError("class_weight_mode must be one of: auto, off, balanced, tempered")
    if class_weight_mode == 'auto':
        # Fixed-key: avoid aggressive weighting (hurts ranking in practice).
        # Variable-key: apply softer weighting for imbalance robustness.
        class_weight = _tempered_class_weight(y_train_idx, num_classes) if variable_key else None
    elif class_weight_mode == 'balanced':
        class_weight = _balanced_class_weight(y_train_idx, num_classes)
    elif class_weight_mode == 'tempered':
        class_weight = _tempered_class_weight(y_train_idx, num_classes)
    
    print(f"  Training samples: {len(x_train)}, Validation samples: {len(x_val)}")
    if class_weight is None:
        print("  Class weights: disabled")
    else:
        print(f"  Class weights: {class_weight}")
    
    # Build model
    print(f"\nBuilding {model_type.upper()} model...")
    label_smoothing = 0.05 if variable_key else 0.0
    if model_type == 'cnn':
        model = build_cnn(input_dim=x.shape[1], num_classes=num_classes, 
                         dropout_rate=0.25 if variable_key else 0.0, 
                         variable_key=variable_key,
                         label_smoothing=label_smoothing)
        # Default batch size for CNN (smaller due to memory)
        if batch_size is None:
            batch_size = 64 if variable_key else 32
    else:
        model = build_mlp(input_dim=x.shape[1], num_classes=num_classes,
                         dropout_rate=0.25 if variable_key else 0.0,
                         variable_key=variable_key,
                         label_smoothing=label_smoothing)
        if batch_size is None:
            batch_size = 256
    
    model.summary()
    
    # Train with callbacks
    print(f"\nTraining for up to {epochs} epochs (batch_size={batch_size})...")
    os.makedirs(os.path.dirname(model_path) if os.path.dirname(model_path) else 'results', exist_ok=True)
    
    if model_type == 'cnn':
        history, model = train_cnn(
            model, x_train, y_train, x_val, y_val,
            epochs=epochs, batch_size=batch_size, model_path=model_path, verbose=2,
            class_weight=class_weight
        )
    else:
        history, model = train_mlp(
            model, x_train, y_train, x_val, y_val,
            epochs=epochs, batch_size=batch_size, model_path=model_path, verbose=2,
            class_weight=class_weight
        )
    
    print(f"\nTraining completed: {len(history.history['loss'])} epochs")
    print(f"  Final val accuracy: {history.history['val_accuracy'][-1]:.4f}")
    print(f"  Final val loss: {history.history['val_loss'][-1]:.4f}")
    
    # Evaluate attack
    print("\nEvaluating attack...")
    # Use up to 20000 attack traces for better results
    max_attack_traces = min(len(x_attack), 20000)
    x_attack = x_attack[:max_attack_traces]
    pt_attack = pt_attack[:max_attack_traces]
    nonce_attack = nonce_attack[:max_attack_traces]
    key_attack = key_attack[:max_attack_traces]
    print(f"  Using {max_attack_traces} attack traces")
    preds_attack = model.predict(x_attack, verbose=0)
    
    # Key recovery
    attack_artifacts = {}
    if not variable_key:
        fixed_key_byte = key_attack[0, target_byte]
        fixed_template = key_attack[0].copy()
        rank, scores = recover_key_byte(
            preds_attack,
            pt_attack,
            nonce_attack,
            true_key_byte=fixed_key_byte,
            target_byte=target_byte,
            key_templates=fixed_template,
        )
        print(f"Fixed-key attack: true byte=0x{fixed_key_byte:02x}, rank={rank}")
        success_rate = 1.0 if rank == 0 else 0.0
        ge_bits = float(np.log2(rank + 1.0))
        print(f"Success rate (rank 0): {success_rate*100:.2f}%")
        
        results = {
            'scenario': 'fixed-key',
            'model': model_type,
            'ascon_mode': ascon_mode,
            'target_byte': int(target_byte),
            'true_key': int(fixed_key_byte),
            'rank': int(rank),
            'guessing_entropy_bits': ge_bits,
            'success_rate': float(success_rate),
            'epochs_trained': len(history.history['loss']),
            'final_val_acc': float(history.history['val_accuracy'][-1]),
            'final_val_loss': float(history.history['val_loss'][-1])
        }
        attack_artifacts = {
            'rank': int(rank),
            'true_key': int(fixed_key_byte),
            'key_scores': scores.astype(np.float64),
        }
    else:
        ranks = recover_variable_key_ranks(preds_attack, pt_attack, nonce_attack, key_attack, target_byte=target_byte)
        stats = summarize_variable_ranks(ranks)
        
        print(f"Variable-key attack statistics:")
        print(f"  Mean rank: {stats['mean_rank']:.2f}")
        print(f"  Success rate (rank=0): {stats['success_rate_rank0']*100:.2f}%")
        print(f"  Success rate (rank<=5): {stats['success_rate_rank5']*100:.2f}%")
        
        results = {
            'scenario': 'variable-key',
            'model': model_type,
            'ascon_mode': ascon_mode,
            'target_byte': int(target_byte),
            'epochs_trained': len(history.history['loss']),
            'final_val_acc': float(history.history['val_accuracy'][-1]),
            'final_val_loss': float(history.history['val_loss'][-1]),
            **{k: float(v) if isinstance(v, (np.floating, np.integer)) else v for k, v in stats.items()}
        }
        attack_artifacts = {'ranks': ranks.astype(np.int32)}
    
    # Save results
    if results_path is None:
        results_path = _default_results_path(model_path)
    os.makedirs(os.path.dirname(results_path) if os.path.dirname(results_path) else 'results', exist_ok=True)
    with open(results_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"Results saved to {results_path}")
    
    if return_attack_artifacts:
        return history, results, attack_artifacts
    return history, results


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Run side-channel attack')
    parser.add_argument('--model', choices=['mlp', 'cnn'], default='mlp', help='Model type')
    parser.add_argument('--dataset', default='data/datasets/fixed_key_dataset.h5', help='Dataset file')
    parser.add_argument('--variable-key', action='store_true', help='Use variable-key scenario')
    parser.add_argument('--standard-mode', action='store_true', 
                       help='Use standard 8-bit HW (9 classes) instead of ASCON 5-bit (6 classes)')
    parser.add_argument('--output', default='results/model.keras', help='Output model path')
    parser.add_argument('--epochs', type=int, default=100, help='Max epochs')
    parser.add_argument('--batch-size', type=int, default=None, help='Batch size')
    parser.add_argument(
        '--class-weight-mode',
        choices=['auto', 'off', 'balanced', 'tempered'],
        default='auto',
        help='Class weighting mode'
    )
    args = parser.parse_args()
    
    run_experiment(args.dataset, args.model, args.variable_key, args.output, 
                  ascon_mode=not args.standard_mode, epochs=args.epochs, batch_size=args.batch_size,
                  class_weight_mode=args.class_weight_mode)

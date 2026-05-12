#!/usr/bin/env python3
"""Execute side-channel attack with a minimal, stable pipeline."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import h5py
import numpy as np
from sklearn.utils.class_weight import compute_class_weight
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
    base, ext = os.path.splitext(model_path)
    if ext.lower() == '.keras':
        return model_path
    return f'{base}.keras'


def _default_results_path(model_path):
    base, _ = os.path.splitext(model_path)
    return f'{base}_results.json'


def _compute_snr(traces, labels, num_classes):
    traces = np.asarray(traces, dtype=np.float64)
    labels = np.asarray(labels, dtype=np.int32)
    means = []
    variances = []
    for cls in range(num_classes):
        cls_tr = traces[labels == cls]
        if cls_tr.shape[0] == 0:
            means.append(np.zeros(traces.shape[1], dtype=np.float64))
            variances.append(np.ones(traces.shape[1], dtype=np.float64))
        else:
            means.append(np.mean(cls_tr, axis=0))
            variances.append(np.var(cls_tr, axis=0) + 1e-12)
    means = np.stack(means, axis=0)
    variances = np.stack(variances, axis=0)
    epsilon = 1e-12
    snr = np.var(means, axis=0) / (np.mean(variances, axis=0) + epsilon)
    snr = np.clip(snr, 0, 1e6)  # Prevent inf values
    return snr.astype(np.float64)


def _select_roi_window(snr, roi_len=400):
    """Pick the roi_len-wide window centred on the highest-SNR sample."""
    n = len(snr)
    L = int(min(max(32, roi_len), n))
    peak = int(snr.argmax())
    start = max(0, peak - L // 2)
    start = min(start, n - L)
    return start, start + L


def run_experiment(
    datafile,
    model_type='mlp',
    variable_key=False,
    model_path='results/model.keras',
    ascon_mode=True,
    epochs=100,
    batch_size=None,
    return_attack_artifacts=False,
    results_path=None,
    label_rounds=None,
    roi_len=400,
):
    """Run side-channel attack experiment.

    Minimal defaults:
    - No class weighting
    - Deterministic split
    - SNR-based ROI selection
    - Z-score normalization after ROI selection
    """
    set_global_seeds(42)
    random.seed(42)
    try:
        tf.config.optimizer.set_jit(False)
    except Exception:
        pass

    model_path = _normalize_model_path(model_path)

    print(f'Loading dataset: {datafile}')
    label_rounds_attr = None
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

        _lr = f.attrs.get('label_rounds', None)
        if _lr is not None:
            label_rounds_attr = int(_lr)

    x = ensure_trace_length(x, target_len=1551)
    x_attack = ensure_trace_length(x_attack, target_len=1551)
    self_test_phase4_core()

    num_classes = 6 if ascon_mode else 9
    print(f"Using {'ASCON 5-bit S-box (6 classes)' if ascon_mode else 'Standard 8-bit (9 classes)'} mode")

    if not ascon_mode:
        raise ValueError('Standard mode label generation is not implemented for this ASCON pipeline.')

    if label_rounds is not None:
        rounds_resolved = int(label_rounds)
    elif label_rounds_attr is not None and label_rounds_attr > 0:
        rounds_resolved = label_rounds_attr
    else:
        rounds_resolved = 2
    print(f'  ASCON label/attack rounds: {rounds_resolved} (CLI override or HDF5 label_rounds attr, default 2)')

    y = generate_hw_labels(key, nonce, pt, target_byte=target_byte, rounds=rounds_resolved)
    if y_stored is not None:
        mismatch_per_class = {}
        for cls in range(num_classes):
            cls_mismatch = np.sum((y == cls) != (y_stored == cls))
            mismatch_per_class[cls] = int(cls_mismatch)
        
        total_mismatch = sum(mismatch_per_class.values())
        if total_mismatch > 0:
            print(f'  WARNING: Label mismatches per class: {mismatch_per_class}')
            print('  Using recomputed labels instead of stored ones')
        else:
            print('  Stored labels verified against recomputed ASCON labels')
    else:
        print('  Labels recomputed from ASCON simulation')
      

    y_cat = to_categorical(y, num_classes=num_classes)
    print(f'  Label distribution: {np.bincount(y, minlength=num_classes)}')

    use_nonce_aux = bool(ascon_mode and nonce is not None and variable_key)
    if nonce is not None:
        x_train, x_val, y_train, y_val, y_train_idx, _, nonce_train, nonce_val = train_test_split(
            x, y_cat, y, nonce, test_size=0.2, stratify=y, random_state=42
        )
    else:
        x_train, x_val, y_train, y_val, y_train_idx, _ = train_test_split(
            x, y_cat, y, test_size=0.2, stratify=y, random_state=42
        )
        nonce_train = nonce_val = None

    if use_nonce_aux:
        nonce_train_f = (nonce_train.astype(np.float32) / 255.0).copy()
        nonce_val_f = (nonce_val.astype(np.float32) / 255.0).copy()
        print('  Model: trace + public nonce auxiliary input (bytes scaled to [0,1])')
    else:
        nonce_train_f = nonce_val_f = None

    # ROI selection from profiling training split only.
    snr = _compute_snr(x_train, y_train_idx, num_classes)
    roi_start, roi_end = _select_roi_window(snr, roi_len=roi_len)
    print(f'  ROI length: {roi_len} samples')
    print(f'  ROI (SNR window): [{roi_start}:{roi_end}] len={roi_end - roi_start}')
    print(f'  SNR stats: max={float(np.max(snr)):.6f}, mean={float(np.mean(snr)):.6f}')

    x_train = x_train[:, roi_start:roi_end]
    x_val = x_val[:, roi_start:roi_end]
    x_attack = x_attack[:, roi_start:roi_end]

    # Normalize after ROI selection.
    mu = np.mean(x_train, axis=0, dtype=np.float64)
    sigma = np.std(x_train, axis=0, dtype=np.float64)
    sigma[sigma < 1e-8] = 1.0

    x_train = ((x_train - mu) / sigma).astype(np.float32)
    x_val = ((x_val - mu) / sigma).astype(np.float32)
    x_attack = ((x_attack - mu) / sigma).astype(np.float32)
    print('  Trace normalization: zscore (post-ROI)')

    print(f'  Training samples: {len(x_train)}, Validation samples: {len(x_val)}')

    # Compute class weights for unbalanced classes
    # class_weights = compute_class_weight('balanced', classes=np.arange(num_classes), y=y_train_idx)
    # class_weights = dict(enumerate(class_weights))
    # print(f'  Class weights: {class_weights}')

    present_classes = np.unique(y_train_idx)

    class_weights = compute_class_weight(
        'balanced',
        classes=present_classes,
        y=y_train_idx
    )

    class_weights = {
        int(c): float(w)
        for c, w in zip(present_classes, class_weights)
    }

    print(f'\nBuilding {model_type.upper()} model...')
    # Nonce aux makes (trace, nonce) easy to memorize; without regularization train_acc explodes while val stalls.
    reg_nonce_fixed = bool(use_nonce_aux and not variable_key)
    if variable_key:
        label_smoothing = 0.05
        dropout_rate = 0.25
    elif reg_nonce_fixed:
        label_smoothing = 0.04
        dropout_rate = 0.38
        print('  Regularization: dropout=0.38 + label_smoothing=0.04 (fixed-key + nonce aux)')
    else:
        label_smoothing = 0.0
        dropout_rate = 0.0

    if model_type == 'cnn':
        model = build_cnn(
            input_dim=x_train.shape[1],
            num_classes=num_classes,
            dropout_rate=dropout_rate,
            variable_key=variable_key,
            label_smoothing=label_smoothing,
            use_nonce_aux=use_nonce_aux,
        )
        if batch_size is None:
            batch_size = 64 if variable_key else 32
    else:
        model = build_mlp(
            input_dim=x_train.shape[1],
            num_classes=num_classes,
            dropout_rate=dropout_rate,
            variable_key=variable_key,
            label_smoothing=label_smoothing,
            use_nonce_aux=use_nonce_aux,
        )
        if batch_size is None:
            batch_size = 256

    model.summary()

    print(f'\nTraining for up to {epochs} epochs (batch_size={batch_size})...')
    os.makedirs(os.path.dirname(model_path) if os.path.dirname(model_path) else 'results', exist_ok=True)

    # Variable-key: val_loss. Fixed-key plain: val_accuracy. Fixed-key + nonce aux: val_loss (val_acc stays ~chance while train memorizes).
    if variable_key:
        monitor = 'val_loss'
        mode = 'min'
        es_patience = 15 if model_type == 'cnn' else 10
        rlr_patience = 7 if model_type == 'cnn' else 5
    elif reg_nonce_fixed:
        monitor = 'val_loss'
        mode = 'min'
        es_patience = 18 if model_type == 'cnn' else 12
        rlr_patience = 7 if model_type == 'cnn' else 5
    else:
        monitor = 'val_accuracy'
        mode = 'max'
        es_patience = 20 if model_type == 'cnn' else 15
        rlr_patience = 8 if model_type == 'cnn' else 6

    print(f'  Callback monitor: {monitor} ({mode})')

    if model_type == 'cnn':
        history, model = train_cnn(
            model,
            x_train,
            y_train,
            x_val,
            y_val,
            epochs=epochs,
            batch_size=batch_size,
            model_path=model_path,
            verbose=2,
            class_weight=class_weights,
            monitor=monitor,
            monitor_mode=mode,
            early_stopping_patience=es_patience,
            reduce_lr_patience=rlr_patience,
            nonce_train=nonce_train_f,
            nonce_val=nonce_val_f,
        )
    else:
        history, model = train_mlp(
            model,
            x_train,
            y_train,
            x_val,
            y_val,
            epochs=epochs,
            batch_size=batch_size,
            model_path=model_path,
            verbose=2,
            class_weight=class_weights,
            monitor=monitor,
            monitor_mode=mode,
            early_stopping_patience=es_patience,
            reduce_lr_patience=rlr_patience,
            nonce_train=nonce_train_f,
            nonce_val=nonce_val_f,
        )

    print(f"\nTraining completed: {len(history.history['loss'])} epochs")
    print(f"  Final val accuracy: {history.history['val_accuracy'][-1]:.4f}")
    print(f"  Final val loss: {history.history['val_loss'][-1]:.4f}")

    print('\nEvaluating attack...')
    max_attack_traces = min(len(x_attack), 20000)
    x_attack = x_attack[:max_attack_traces]
    pt_attack = pt_attack[:max_attack_traces]
    nonce_attack = nonce_attack[:max_attack_traces]
    key_attack = key_attack[:max_attack_traces]
    print(f'  Using {max_attack_traces} attack traces')

    if model_type == 'cnn':
        x_pred = x_attack.reshape((x_attack.shape[0], x_attack.shape[1], 1))
    else:
        x_pred = x_attack
    if use_nonce_aux:
        nonce_attack_f = (nonce_attack.astype(np.float32) / 255.0).copy()
        preds_attack = model.predict([x_pred, nonce_attack_f], verbose=0)
    else:
        preds_attack = model.predict(x_pred, verbose=0)

    attack_artifacts = {}
    if not variable_key:
        fixed_key_byte = int(key_attack[0, target_byte])
        unique_attack_keys = np.unique(key_attack, axis=0)
        print(f'  Fixed-key check: unique attack keys = {len(unique_attack_keys)}')

        key_templates = key_attack[0].copy() if len(unique_attack_keys) == 1 else key_attack
        rank, scores = recover_key_byte(
            preds_attack,
            pt_attack,
            nonce_attack,
            true_key_byte=fixed_key_byte,
            target_byte=target_byte,
            key_templates=key_templates,
            rounds=rounds_resolved,
        )

        print(f'Fixed-key attack: true byte=0x{fixed_key_byte:02x}, rank={rank}')
        success_rate = 1.0 if rank == 0 else 0.0
        ge_bits = float(np.log2(rank + 1.0))
        print(f'Success rate (rank 0): {success_rate*100:.2f}%')

        results = {
            'scenario': 'fixed-key',
            'model': model_type,
            'ascon_mode': ascon_mode,
            'use_nonce_aux': bool(use_nonce_aux),
            'label_rounds': int(rounds_resolved),
            'target_byte': int(target_byte),
            'true_key': int(fixed_key_byte),
            'rank': int(rank),
            'guessing_entropy_bits': ge_bits,
            'success_rate': float(success_rate),
            'epochs_trained': len(history.history['loss']),
            'final_val_acc': float(history.history['val_accuracy'][-1]),
            'final_val_loss': float(history.history['val_loss'][-1]),
            'roi_start': int(roi_start),
            'roi_end': int(roi_end),
            'snr_max': float(np.max(snr)),
            'snr_mean': float(np.mean(snr)),
        }
        attack_artifacts = {
            'rank': int(rank),
            'true_key': int(fixed_key_byte),
            'key_scores': scores.astype(np.float64),
        }
    else:
        ranks = recover_variable_key_ranks(
            preds_attack,
            pt_attack,
            nonce_attack,
            key_attack,
            target_byte=target_byte,
            rounds=rounds_resolved,
        )
        stats = summarize_variable_ranks(ranks)

        print('Variable-key attack statistics:')
        print(f"  Mean rank: {stats['mean_rank']:.2f}")
        print(f"  Success rate (rank=0): {stats['success_rate_rank0']*100:.2f}%")
        print(f"  Success rate (rank<=5): {stats['success_rate_rank5']*100:.2f}%")

        results = {
            'scenario': 'variable-key',
            'model': model_type,
            'ascon_mode': ascon_mode,
            'use_nonce_aux': bool(use_nonce_aux),
            'label_rounds': int(rounds_resolved),
            'target_byte': int(target_byte),
            'epochs_trained': len(history.history['loss']),
            'final_val_acc': float(history.history['val_accuracy'][-1]),
            'final_val_loss': float(history.history['val_loss'][-1]),
            'roi_start': int(roi_start),
            'roi_end': int(roi_end),
            'snr_max': float(np.max(snr)),
            'snr_mean': float(np.mean(snr)),
            **{k: float(v) if isinstance(v, (np.floating, np.integer)) else v for k, v in stats.items()},
        }
        attack_artifacts = {'ranks': ranks.astype(np.int32)}

    if results_path is None:
        results_path = _default_results_path(model_path)
    os.makedirs(os.path.dirname(results_path) if os.path.dirname(results_path) else 'results', exist_ok=True)
    with open(results_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    print(f'Results saved to {results_path}')

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
        '--label-rounds',
        type=int,
        default=None,
        help='Permutation rounds before probed S-box (0–12). Default: HDF5 attr label_rounds or 2. Must match dataset.',
    )
    args = parser.parse_args()

    # Default to MLP for ASCON mode (better for weak leakage)
    if not args.standard_mode:
        args.model = 'mlp'

    run_experiment(
        args.dataset,
        args.model,
        args.variable_key,
        args.output,
        ascon_mode=not args.standard_mode,
        epochs=args.epochs,
        batch_size=args.batch_size,
        label_rounds=args.label_rounds,
    )

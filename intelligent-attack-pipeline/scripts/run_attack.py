#!/usr/bin/env python3
"""Execute side-channel attack with MLP or CNN model."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import h5py
import numpy as np
from tensorflow.keras.utils import to_categorical
from sklearn.model_selection import train_test_split

from src.models.mlp import build_mlp
from src.models.cnn import build_cnn
from src.attacks.key_recovery import generate_labels, key_recovery_from_predictions, per_trace_variable_key_success


def run_experiment(datafile, model_type='mlp', variable_key=False, model_path='results/model.h5'):
    """Run side-channel attack experiment.
    
    Args:
        datafile: Path to HDF5 dataset
        model_type: 'mlp' or 'cnn'
        variable_key: Use variable-key scenario
        model_path: Where to save trained model
    """
    print(f"Loading dataset: {datafile}")
    with h5py.File(datafile, 'r') as f:
        x = f['Profiling_traces/traces'][:]
        pt = f['Profiling_traces/metadata/plaintext'][:]
        key = f['Profiling_traces/metadata/key'][:]
        
        x_attack = f['Attack_traces/traces'][:]
        pt_attack = f['Attack_traces/metadata/plaintext'][:]
        key_attack = f['Attack_traces/metadata/key'][:]
    
    y = generate_labels(pt, key, target_byte=0)
    y_cat = to_categorical(y, num_classes=9)
    
    x_train, x_val, y_train, y_val = train_test_split(
        x, y_cat, test_size=0.2, stratify=y, random_state=42
    )
    
    # Build model
    print(f"Building {model_type.upper()} model...")
    if model_type == 'cnn':
        model = build_cnn(input_dim=x.shape[1], num_classes=9, 
                         dropout_rate=0.25 if variable_key else 0.0, 
                         variable_key=variable_key)
    else:
        model = build_mlp(input_dim=x.shape[1], num_classes=9,
                         dropout_rate=0.25 if variable_key else 0.0,
                         variable_key=variable_key)
    
    # Train
    epochs = 70 if variable_key else 50
    print(f"Training for {epochs} epochs...")
    history = model.fit(x_train, y_train, epochs=epochs, batch_size=256,
                       validation_data=(x_val, y_val), verbose=2)
    
    model.save(model_path)
    print(f"Model saved to {model_path}")
    
    # Evaluate attack
    print("Evaluating attack...")
    preds_attack = model.predict(x_attack)
    
    if not variable_key:
        fixed_key_byte = key_attack[0, 0]
        rank, scores = key_recovery_from_predictions(preds_attack, pt_attack, fixed_key_byte)
        print(f"Fixed-key attack: true byte=0x{fixed_key_byte:02x}, rank={rank}")
        success_rate = 1.0 if rank == 0 else 0.0
        print(f"Success rate (rank 0): {success_rate*100:.2f}%")
    else:
        ranks = per_trace_variable_key_success(preds_attack, pt_attack, key_attack)
        success_rate = np.mean(ranks == 0)
        mean_rank = np.mean(ranks)
        print(f"Variable-key success rate (rank0): {success_rate*100:.2f}%")
        print(f"Variable-key mean rank: {mean_rank:.2f}")
    
    return history


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Run side-channel attack')
    parser.add_argument('--model', choices=['mlp', 'cnn'], default='mlp', help='Model type')
    parser.add_argument('--dataset', default='data/datasets/fixed_key_dataset.h5', help='Dataset file')
    parser.add_argument('--variable-key', action='store_true', help='Use variable-key scenario')
    parser.add_argument('--output', default='results/model.h5', help='Output model path')
    args = parser.parse_args()
    
    run_experiment(args.dataset, args.model, args.variable_key, args.output)

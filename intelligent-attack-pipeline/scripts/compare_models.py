#!/usr/bin/env python3
"""Compare MLP vs CNN performance on side-channel attacks."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
from run_attack import run_experiment


def compare_models(dataset='data/datasets/fixed_key_dataset.h5', variable_key=False):
    """Compare MLP and CNN on same dataset.
    
    Args:
        dataset: Path to HDF5 dataset
        variable_key: Whether to use variable-key scenario
    """
    results = []
    
    for model_type in ['mlp', 'cnn']:
        print(f"\n{'='*50}")
        print(f"Running {model_type.upper()} experiment...")
        print('='*50)
        
        history = run_experiment(
            dataset, 
            model_type=model_type,
            variable_key=variable_key,
            model_path=f'results/{model_type}_model.keras'
        )
        
        results.append({
            'model': model_type,
            'final_loss': history.history['loss'][-1],
            'final_val_loss': history.history['val_loss'][-1],
            'final_acc': history.history['accuracy'][-1],
            'final_val_acc': history.history['val_accuracy'][-1]
        })
    
    # Print comparison table
    df = pd.DataFrame(results)
    print("\n" + "="*50)
    print("COMPARISON RESULTS")
    print("="*50)
    print(df.to_string(index=False))
    
    # Save results
    df.to_csv('results/comparison_results.csv', index=False)
    print("\nResults saved to results/comparison_results.csv")
    
    return df


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Compare MLP vs CNN')
    parser.add_argument('--dataset', default='data/datasets/fixed_key_dataset.h5')
    parser.add_argument('--variable-key', action='store_true')
    args = parser.parse_args()
    
    compare_models(args.dataset, args.variable_key)

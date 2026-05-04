#!/usr/bin/env python3
"""Compare MLP vs CNN performance for ASCON-128 side-channel attacks.

This script performs a systematic comparison of Multi-Layer Perceptron (MLP)
and Convolutional Neural Network (CNN) architectures for ASCON S-box leakage
targeting with both fixed-key and variable-key scenarios.

Includes statistical tests (t-test) to determine if CNN significantly outperforms MLP.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import time
import json
from scipy import stats
from run_attack import run_experiment


def run_single_experiment(dataset_path, model_type, variable_key, output_dir, epochs=100):
    """Run a single experiment and return results.
    
    Args:
        dataset_path: Path to HDF5 dataset
        model_type: 'mlp' or 'cnn'
        variable_key: Whether to use variable-key scenario
        output_dir: Output directory
        epochs: Max training epochs
    
    Returns:
        dict: Results including history and metrics
    """
    scenario = 'variable' if variable_key else 'fixed'
    name = f"{scenario}_{model_type}"
    
    print(f"\n{'='*60}")
    print(f"Running: {name.upper()}")
    print('='*60)
    
    start_time = time.time()
    
    model_path = f"{output_dir}/{name}_model.h5"
    history, results = run_experiment(
        dataset_path,
        model_type=model_type,
        variable_key=variable_key,
        model_path=model_path,
        epochs=epochs
    )
    
    training_time = time.time() - start_time
    
    return {
        'model': model_type,
        'scenario': scenario,
        'name': name,
        'history': history,
        'results': results,
        'training_time': training_time,
        'epochs_trained': len(history.history['loss']),
        'final_val_acc': history.history['val_accuracy'][-1],
        'final_val_loss': history.history['val_loss'][-1],
        'final_train_acc': history.history['accuracy'][-1],
        'final_train_loss': history.history['loss'][-1]
    }


def run_comparison(dataset_fixed, dataset_variable=None, output_dir='results', num_runs=1, epochs=100):
    """Run complete MLP vs CNN comparison with optional multiple runs for statistics.
    
    Args:
        dataset_fixed: Path to fixed-key HDF5 dataset
        dataset_variable: Path to variable-key dataset (optional)
        output_dir: Directory for output files
        num_runs: Number of runs per configuration (for statistical testing)
        epochs: Maximum training epochs
    """
    os.makedirs(output_dir, exist_ok=True)
    
    all_results = []
    all_histories = {}
    
    # Run configurations
    # Fixed-key experiments
    for run in range(num_runs):
        print(f"\n{'#'*60}")
        print(f"RUN {run + 1}/{num_runs}")
        print('#'*60)
        
        # Fixed-Key MLP
        result = run_single_experiment(dataset_fixed, 'mlp', False, output_dir, epochs)
        all_results.append(result)
        all_histories[f'fixed_mlp_run{run}'] = result['history']
        
        # Fixed-Key CNN
        result = run_single_experiment(dataset_fixed, 'cnn', False, output_dir, epochs)
        all_results.append(result)
        all_histories[f'fixed_cnn_run{run}'] = result['history']
        
        # Variable-Key experiments (if dataset provided)
        if dataset_variable:
            # Variable-Key MLP
            result = run_single_experiment(dataset_variable, 'mlp', True, output_dir, epochs)
            all_results.append(result)
            all_histories[f'variable_mlp_run{run}'] = result['history']
            
            # Variable-Key CNN
            result = run_single_experiment(dataset_variable, 'cnn', True, output_dir, epochs)
            all_results.append(result)
            all_histories[f'variable_cnn_run{run}'] = result['history']
    
    # Aggregate results
    results_df = aggregate_results(all_results)
    
    # Print comparison table
    print("\n" + "="*80)
    print("MLP vs CNN COMPARISON RESULTS")
    print("="*80)
    print(results_df.to_string(index=False))
    
    # Save to CSV
    csv_path = f"{output_dir}/comparison_table.csv"
    results_df.to_csv(csv_path, index=False)
    print(f"\nComparison table saved to {csv_path}")
    
    # Statistical tests (if multiple runs)
    if num_runs > 1:
        stat_results = perform_statistical_tests(all_results)
        stat_path = f"{output_dir}/statistical_tests.txt"
        with open(stat_path, 'w') as f:
            f.write(stat_results)
        print(f"Statistical test results saved to {stat_path}")
    
    # Generate visualizations
    plot_comparison(all_results, output_dir)
    plot_training_curves(all_histories, output_dir)
    
    # Save full results as JSON
    json_results = []
    for r in all_results:
        json_results.append({
            'model': r['model'],
            'scenario': r['scenario'],
            'epochs_trained': r['epochs_trained'],
            'training_time': r['training_time'],
            'final_val_acc': r['final_val_acc'],
            'final_val_loss': r['final_val_loss'],
            'attack_results': r['results']
        })
    
    json_path = f"{output_dir}/comparison_results.json"
    with open(json_path, 'w') as f:
        json.dump(json_results, f, indent=2)
    print(f"Full results saved to {json_path}")
    
    return results_df


def aggregate_results(all_results):
    """Aggregate results across multiple runs.
    
    Args:
        all_results: List of result dictionaries
    
    Returns:
        DataFrame: Aggregated results
    """
    # Group by model and scenario
    grouped = {}
    for r in all_results:
        key = (r['model'], r['scenario'])
        if key not in grouped:
            grouped[key] = []
        grouped[key].append(r)
    
    aggregated = []
    for (model, scenario), runs in grouped.items():
        n = len(runs)
        
        # Compute mean and std
        val_accs = [r['final_val_acc'] for r in runs]
        val_losses = [r['final_val_loss'] for r in runs]
        times = [r['training_time'] for r in runs]
        epochs_list = [r['epochs_trained'] for r in runs]
        
        # Get attack success rates
        success_rates = [r['results'].get('success_rate', r['results'].get('success_rate_rank0', 0)) for r in runs]
        mean_ranks = [r['results'].get('mean_rank', 0) for r in runs]
        
        aggregated.append({
            'Model': model.upper(),
            'Scenario': scenario.title() + '-Key',
            'Runs': n,
            'Val_Acc_Mean': np.mean(val_accs),
            'Val_Acc_Std': np.std(val_accs) if n > 1 else 0,
            'Val_Loss_Mean': np.mean(val_losses),
            'Val_Loss_Std': np.std(val_losses) if n > 1 else 0,
            'Time_Mean_sec': np.mean(times),
            'Epochs_Mean': np.mean(epochs_list),
            'Success_Rate_Mean': np.mean(success_rates),
            'Success_Rate_Std': np.std(success_rates) if n > 1 else 0,
            'Mean_Rank': np.mean(mean_ranks) if mean_ranks[0] > 0 else 0
        })
    
    return pd.DataFrame(aggregated)


def perform_statistical_tests(all_results):
    """Perform paired t-tests to compare MLP vs CNN.
    
    Args:
        all_results: List of result dictionaries
    
    Returns:
        str: Formatted statistical test results
    """
    output = ["STATISTICAL TESTS (MLP vs CNN)", "="*60, ""]
    
    # Group by scenario
    scenarios = ['fixed', 'variable']
    
    for scenario in scenarios:
        mlp_results = [r for r in all_results if r['model'] == 'mlp' and r['scenario'] == scenario]
        cnn_results = [r for r in all_results if r['model'] == 'cnn' and r['scenario'] == scenario]
        
        if len(mlp_results) < 2 or len(cnn_results) < 2:
            continue
        
        # Extract metrics
        mlp_accs = [r['final_val_acc'] for r in mlp_results]
        cnn_accs = [r['final_val_acc'] for r in cnn_results]
        
        mlp_success = [r['results'].get('success_rate', r['results'].get('success_rate_rank0', 0)) 
                       for r in mlp_results]
        cnn_success = [r['results'].get('success_rate', r['results'].get('success_rate_rank0', 0)) 
                       for r in cnn_results]
        
        # Perform t-tests
        acc_tstat, acc_pval = stats.ttest_ind(mlp_accs, cnn_accs)
        success_tstat, success_pval = stats.ttest_ind(mlp_success, cnn_success)
        
        output.append(f"\n{scenario.upper()}-KEY SCENARIO:")
        output.append(f"  Validation Accuracy:")
        output.append(f"    MLP:  {np.mean(mlp_accs):.4f} ± {np.std(mlp_accs):.4f}")
        output.append(f"    CNN:  {np.mean(cnn_accs):.4f} ± {np.std(cnn_accs):.4f}")
        output.append(f"    t-stat: {acc_tstat:.4f}, p-value: {acc_pval:.4f}")
        output.append(f"    Significant (p<0.05): {'YES' if acc_pval < 0.05 else 'NO'}")
        
        output.append(f"  Attack Success Rate:")
        output.append(f"    MLP:  {np.mean(mlp_success):.4f} ± {np.std(mlp_success):.4f}")
        output.append(f"    CNN:  {np.mean(cnn_success):.4f} ± {np.std(cnn_success):.4f}")
        output.append(f"    t-stat: {success_tstat:.4f}, p-value: {success_pval:.4f}")
        output.append(f"    Significant (p<0.05): {'YES' if success_pval < 0.05 else 'NO'}")
    
    output.append("")
    output.append("Interpretation:")
    output.append("  - p-value < 0.05: CNN is significantly better than MLP")
    output.append("  - p-value > 0.05: No significant difference")
    
    return '\n'.join(output)


def plot_comparison(results, output_dir):
    """Generate comparison plots.
    
    Args:
        results: List of result dictionaries
        output_dir: Output directory for plots
    """
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    
    # Extract data by scenario using correct keys
    fixed_key = [r for r in results if r['scenario'] == 'fixed']
    variable_key = [r for r in results if r['scenario'] == 'variable']
    
    # 1. Validation Accuracy Comparison
    ax = axes[0, 0]
    models = ['MLP', 'CNN']
    
    # Aggregate by model type
    fixed_mlp_acc = np.mean([r['final_val_acc'] for r in fixed_key if r['model'] == 'mlp'])
    fixed_cnn_acc = np.mean([r['final_val_acc'] for r in fixed_key if r['model'] == 'cnn'])
    var_mlp_acc = np.mean([r['final_val_acc'] for r in variable_key if r['model'] == 'mlp'])
    var_cnn_acc = np.mean([r['final_val_acc'] for r in variable_key if r['model'] == 'cnn'])
    
    fixed_accs = [fixed_mlp_acc, fixed_cnn_acc]
    var_accs = [var_mlp_acc, var_cnn_acc]
    
    x = np.arange(len(models))
    width = 0.35
    ax.bar(x - width/2, fixed_accs, width, label='Fixed-Key', alpha=0.8, color='steelblue')
    ax.bar(x + width/2, var_accs, width, label='Variable-Key', alpha=0.8, color='coral')
    ax.set_ylabel('Validation Accuracy')
    ax.set_title('Model Accuracy Comparison')
    ax.set_xticks(x)
    ax.set_xticklabels(models)
    ax.legend()
    ax.set_ylim(0, 1)
    ax.grid(axis='y', alpha=0.3)
    
    # 2. Attack Success Rate
    ax = axes[0, 1]
    
    # Get success rates from attack results
    def get_success_rate(r):
        res = r['results']
        return res.get('success_rate', res.get('success_rate_rank0', 0))
    
    fixed_mlp_success = np.mean([get_success_rate(r) for r in fixed_key if r['model'] == 'mlp']) if fixed_key else 0
    fixed_cnn_success = np.mean([get_success_rate(r) for r in fixed_key if r['model'] == 'cnn']) if fixed_key else 0
    var_mlp_success = np.mean([get_success_rate(r) for r in variable_key if r['model'] == 'mlp']) if variable_key else 0
    var_cnn_success = np.mean([get_success_rate(r) for r in variable_key if r['model'] == 'cnn']) if variable_key else 0
    
    fixed_success = [fixed_mlp_success, fixed_cnn_success]
    var_success = [var_mlp_success, var_cnn_success]
    
    ax.bar(x - width/2, fixed_success, width, label='Fixed-Key', alpha=0.8, color='steelblue')
    ax.bar(x + width/2, var_success, width, label='Variable-Key', alpha=0.8, color='coral')
    ax.set_ylabel('Attack Success Rate')
    ax.set_title('Key Recovery Success (Rank=0)')
    ax.set_xticks(x)
    ax.set_xticklabels(models)
    ax.legend()
    ax.set_ylim(0, 1)
    ax.grid(axis='y', alpha=0.3)
    
    # 3. Training Time
    ax = axes[1, 0]
    
    fixed_mlp_time = np.mean([r['training_time'] for r in fixed_key if r['model'] == 'mlp']) if fixed_key else 0
    fixed_cnn_time = np.mean([r['training_time'] for r in fixed_key if r['model'] == 'cnn']) if fixed_key else 0
    var_mlp_time = np.mean([r['training_time'] for r in variable_key if r['model'] == 'mlp']) if variable_key else 0
    var_cnn_time = np.mean([r['training_time'] for r in variable_key if r['model'] == 'cnn']) if variable_key else 0
    
    fixed_times = [fixed_mlp_time, fixed_cnn_time]
    var_times = [var_mlp_time, var_cnn_time]
    
    ax.bar(x - width/2, fixed_times, width, label='Fixed-Key', alpha=0.8, color='steelblue')
    ax.bar(x + width/2, var_times, width, label='Variable-Key', alpha=0.8, color='coral')
    ax.set_ylabel('Training Time (seconds)')
    ax.set_title('Training Time Comparison')
    ax.set_xticks(x)
    ax.set_xticklabels(models)
    ax.legend()
    ax.grid(axis='y', alpha=0.3)
    
    # 4. Mean Rank (for variable-key)
    ax = axes[1, 1]
    
    def get_mean_rank(r):
        res = r['results']
        return res.get('mean_rank', 0)
    
    var_mlp_rank = np.mean([get_mean_rank(r) for r in variable_key if r['model'] == 'mlp']) if variable_key else 0
    var_cnn_rank = np.mean([get_mean_rank(r) for r in variable_key if r['model'] == 'cnn']) if variable_key else 0
    
    ranks = [var_mlp_rank, var_cnn_rank]
    colors = ['steelblue', 'coral']
    
    ax.bar(models, ranks, color=colors, alpha=0.8)
    ax.set_ylabel('Mean Key Rank')
    ax.set_title('Variable-Key: Mean Rank (lower is better)')
    ax.grid(axis='y', alpha=0.3)
    ax.axhline(y=128, color='red', linestyle='--', alpha=0.5, label='Random guess')
    ax.legend()
    
    plt.tight_layout()
    plot_path = f"{output_dir}/mlp_vs_cnn_comparison.png"
    plt.savefig(plot_path, dpi=150, bbox_inches='tight')
    print(f"Comparison plot saved to {plot_path}")
    plt.close()


def plot_training_curves(histories, output_dir):
    """Plot training curves for all models.
    
    Args:
        histories: Dict of histories keyed by name
        output_dir: Output directory
    """
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    
    scenarios = ['fixed', 'variable']
    models = ['mlp', 'cnn']
    
    for i, scenario in enumerate(scenarios):
        for j, model in enumerate(models):
            ax = axes[i, j]
            
            # Find all runs for this config
            matching = [k for k in histories.keys() if k.startswith(f'{scenario}_{model}')]
            
            if not matching:
                ax.text(0.5, 0.5, 'No data', ha='center', va='center', transform=ax.transAxes)
                ax.set_title(f'{scenario.title()}-Key {model.upper()}')
                continue
            
            # Plot all runs
            for k in matching:
                h = histories[k]
                epochs = range(1, len(h.history['loss']) + 1)
                ax.plot(epochs, h.history['loss'], 'b-', alpha=0.3, label='Train loss' if k == matching[0] else '')
                ax.plot(epochs, h.history['val_loss'], 'r-', alpha=0.3, label='Val loss' if k == matching[0] else '')
            
            ax.set_xlabel('Epoch')
            ax.set_ylabel('Loss')
            ax.set_title(f'{scenario.title()}-Key {model.upper()}')
            ax.legend()
            ax.grid(alpha=0.3)
    
    plt.tight_layout()
    plot_path = f"{output_dir}/training_curves.png"
    plt.savefig(plot_path, dpi=150, bbox_inches='tight')
    print(f"Training curves saved to {plot_path}")
    plt.close()


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Compare MLP vs CNN for ASCON SCA')
    parser.add_argument('--dataset-fixed', default='data/datasets/fixed_key_dataset.h5',
                       help='Fixed-key dataset file path')
    parser.add_argument('--dataset-variable', default='data/datasets/variable_key_dataset.h5',
                       help='Variable-key dataset file path')
    parser.add_argument('--output-dir', default='results',
                       help='Output directory for results')
    parser.add_argument('--num-runs', type=int, default=1,
                       help='Number of runs per configuration (for statistical testing)')
    parser.add_argument('--epochs', type=int, default=100,
                       help='Maximum training epochs')
    args = parser.parse_args()
    
    run_comparison(args.dataset_fixed, args.dataset_variable, 
                  args.output_dir, args.num_runs, args.epochs)

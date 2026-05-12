#!/usr/bin/env python3
"""Phase 4 variable-key deep-learning attack runner."""
import os
import sys
import json
from datetime import datetime, timezone

import numpy as np

try:
    import matplotlib.pyplot as plt
except ImportError:
    plt = None


def history_to_dict(history):
    """Convert Keras History object to plain JSON-serializable dict."""
    out = {}
    for key, values in history.history.items():
        out[key] = [float(v) for v in values]
    out["epochs_trained"] = len(history.history.get("loss", []))
    return out


def plot_training_curves(history_dict, output_path, title):
    """Save training loss/accuracy curves."""
    if plt is None:
        return False
    epochs = range(1, history_dict["epochs_trained"] + 1)
    fig, axes = plt.subplots(1, 2, figsize=(12, 4))

    axes[0].plot(epochs, history_dict.get("loss", []), label="train_loss")
    axes[0].plot(epochs, history_dict.get("val_loss", []), label="val_loss")
    axes[0].set_title(f"{title} - Loss")
    axes[0].set_xlabel("Epoch")
    axes[0].set_ylabel("Loss")
    axes[0].grid(alpha=0.25)
    axes[0].legend()

    axes[1].plot(epochs, history_dict.get("accuracy", []), label="train_acc")
    axes[1].plot(epochs, history_dict.get("val_accuracy", []), label="val_acc")
    axes[1].set_title(f"{title} - Accuracy")
    axes[1].set_xlabel("Epoch")
    axes[1].set_ylabel("Accuracy")
    axes[1].grid(alpha=0.25)
    axes[1].legend()

    fig.tight_layout()
    fig.savefig(output_path, dpi=150)
    plt.close(fig)
    return True


def plot_rank_histogram(ranks, output_path):
    """Plot histogram of per-trace key rank."""
    if plt is None:
        return False
    fig, ax = plt.subplots(figsize=(10, 4))
    bins = np.arange(0, 257, 8)
    ax.hist(ranks, bins=bins, alpha=0.85, edgecolor="black", linewidth=0.4)
    ax.set_xlabel("Per-trace rank of correct key byte (0 is best)")
    ax.set_ylabel("Trace count")
    ax.set_title("Variable-Key Key-Rank Distribution")
    ax.grid(alpha=0.25)
    fig.tight_layout()
    fig.savefig(output_path, dpi=150)
    plt.close(fig)
    return True


def save_json(path, payload):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Phase 4 variable-key attack")
    parser.add_argument("--dataset", default="data/datasets/ascon_variable_key_10k.h5", help="Variable-key dataset path")
    parser.add_argument("--model", choices=["mlp", "cnn"], default="cnn", help="Model type")
    parser.add_argument("--epochs", type=int, default=70, help="Max epochs")
    parser.add_argument("--batch-size", type=int, default=None, help="Batch size override")
    parser.add_argument("--roi-len", type=int, default=400, help="ROI window length in samples")
    parser.add_argument("--output-dir", default="results/phase4", help="Output directory")
    parser.add_argument(
        "--label-rounds",
        type=int,
        default=None,
        help="ASCON HW label rounds (default: HDF5 label_rounds attr or 2). Must match dataset.",
    )
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    from run_attack import run_experiment

    model_path = os.path.join(args.output_dir, "model_variable_key.keras")
    results_path = os.path.join(args.output_dir, "variable_key_results.json")
    history, results, artifacts = run_experiment(
        datafile=args.dataset,
        model_type=args.model,
        variable_key=True,
        model_path=model_path,
        ascon_mode=True,
        epochs=args.epochs,
        batch_size=args.batch_size,
        results_path=results_path,
        return_attack_artifacts=True,
        label_rounds=args.label_rounds,
        roi_len=args.roi_len,
    )

    history_dict = history_to_dict(history)
    ranks = np.asarray(artifacts["ranks"], dtype=np.int32)

    history_path = os.path.join(args.output_dir, "variable_key_history.json")
    ranks_path = os.path.join(args.output_dir, "variable_key_ranks.npy")
    curves_plot = os.path.join(args.output_dir, "variable_key_training_curves.png")
    rank_plot = os.path.join(args.output_dir, "variable_key_rank_hist.png")

    np.save(ranks_path, ranks)
    save_json(history_path, history_dict)
    save_json(results_path, results)
    have_curves_plot = plot_training_curves(history_dict, curves_plot, "Variable-Key Attack")
    have_rank_plot = plot_rank_histogram(ranks, rank_plot)

    summary = {
        "phase": "phase4",
        "scenario": "variable-key",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "dataset": args.dataset,
        "model_type": args.model,
        "model_file": model_path,
        "results_file": results_path,
        "history_file": history_path,
        "ranks_file": ranks_path,
        "training_curves_plot": curves_plot if have_curves_plot else "",
        "rank_histogram_plot": rank_plot if have_rank_plot else "",
        "success_rate_rank0": float(results["success_rate_rank0"]),
        "mean_rank": float(results["mean_rank"]),
        "plots_generated": bool(have_curves_plot and have_rank_plot),
    }
    save_json(os.path.join(args.output_dir, "variable_key_summary.json"), summary)

    print("\nVariable-key phase complete.")
    print(f"  Model: {model_path}")
    print(f"  Results: {results_path}")
    print(f"  Mean rank: {results['mean_rank']:.2f}")
    if plt is None:
        print("  Note: matplotlib not installed, skipped PNG plot generation.")


if __name__ == "__main__":
    main()

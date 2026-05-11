#!/usr/bin/env python3
"""Phase 4 fixed-key deep-learning attack runner."""
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


def plot_key_scores(key_scores, true_key, output_path):
    """Plot key log-likelihood scores for 256 key hypotheses."""
    if plt is None:
        return False
    x = np.arange(256)
    fig, ax = plt.subplots(figsize=(12, 4))
    ax.plot(x, key_scores, linewidth=1.0)
    ax.axvline(true_key, color="red", linestyle="--", linewidth=1.2, label=f"true key: 0x{true_key:02x}")
    ax.set_xlabel("Key hypothesis (0..255)")
    ax.set_ylabel("Accumulated log-probability")
    ax.set_title("Fixed-Key Key-Hypothesis Scores")
    ax.grid(alpha=0.25)
    ax.legend()
    fig.tight_layout()
    fig.savefig(output_path, dpi=150)
    plt.close(fig)
    return True


def save_json(path, payload):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Phase 4 fixed-key attack")
    parser.add_argument("--dataset", default="data/datasets/ascon_fixed_key_10k.h5", help="Fixed-key dataset path")
    parser.add_argument("--model", choices=["mlp", "cnn"], default="cnn", help="Model type")
    parser.add_argument("--epochs", type=int, default=50, help="Max epochs")
    parser.add_argument("--batch-size", type=int, default=None, help="Batch size override")
    parser.add_argument(
        "--class-weight-mode",
        choices=["auto", "off", "balanced", "tempered"],
        default="off",
        help="Class weighting policy for training"
    )
    parser.add_argument("--output-dir", default="results/phase4", help="Output directory")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    from run_attack import run_experiment

    model_path = os.path.join(args.output_dir, "model_fixed_key.keras")
    results_path = os.path.join(args.output_dir, "fixed_key_results.json")
    history, results, artifacts = run_experiment(
        datafile=args.dataset,
        model_type=args.model,
        variable_key=False,
        model_path=model_path,
        ascon_mode=True,
        epochs=args.epochs,
        batch_size=args.batch_size,
        class_weight_mode=args.class_weight_mode,
        results_path=results_path,
        return_attack_artifacts=True,
    )

    history_dict = history_to_dict(history)
    key_scores = np.asarray(artifacts["key_scores"], dtype=np.float64)
    true_key = int(artifacts["true_key"])

    history_path = os.path.join(args.output_dir, "fixed_key_history.json")
    scores_path = os.path.join(args.output_dir, "fixed_key_key_scores.npy")
    curves_plot = os.path.join(args.output_dir, "fixed_key_training_curves.png")
    rank_plot = os.path.join(args.output_dir, "fixed_key_key_scores.png")

    np.save(scores_path, key_scores)
    save_json(history_path, history_dict)
    save_json(results_path, results)
    have_curves_plot = plot_training_curves(history_dict, curves_plot, "Fixed-Key Attack")
    have_rank_plot = plot_key_scores(key_scores, true_key, rank_plot)

    ranked = np.argsort(-key_scores)
    top10 = [int(v) for v in ranked[:10]]

    summary = {
        "phase": "phase4",
        "scenario": "fixed-key",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "dataset": args.dataset,
        "model_type": args.model,
        "model_file": model_path,
        "results_file": results_path,
        "history_file": history_path,
        "key_scores_file": scores_path,
        "training_curves_plot": curves_plot if have_curves_plot else "",
        "key_rank_plot": rank_plot if have_rank_plot else "",
        "rank": int(results["rank"]),
        "top10_key_hypotheses": top10,
        "plots_generated": bool(have_curves_plot and have_rank_plot),
    }
    save_json(os.path.join(args.output_dir, "fixed_key_summary.json"), summary)

    print("\nFixed-key phase complete.")
    print(f"  Model: {model_path}")
    print(f"  Results: {results_path}")
    print(f"  Rank: {results['rank']}")
    if plt is None:
        print("  Note: matplotlib not installed, skipped PNG plot generation.")


if __name__ == "__main__":
    main()

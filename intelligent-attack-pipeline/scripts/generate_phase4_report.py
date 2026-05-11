#!/usr/bin/env python3
"""Generate Phase 4 results and analysis report from attack outputs."""
import os
import json
from datetime import datetime, timezone


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def model_architecture_text(model_type, variable_key):
    if model_type == "cnn":
        if variable_key:
            return (
                "- CNN input: trace length 1551\n"
                "- Conv1D(64, k=11) -> MaxPool(2)\n"
                "- Conv1D(128, k=7) -> MaxPool(2)\n"
                "- Conv1D(256, k=5) -> MaxPool(2) -> Dropout(0.25)\n"
                "- Dense(512) -> Dropout(0.25) -> Dense(256) -> Dense(6, softmax)\n"
            )
        return (
            "- CNN input: trace length 1551\n"
            "- Conv1D(64, k=11) -> MaxPool(2)\n"
            "- Conv1D(128, k=7) -> MaxPool(2)\n"
            "- Dense(256) -> Dense(6, softmax)\n"
        )

    if variable_key:
        return (
            "- MLP input: trace length 1551\n"
            "- Dense(512) -> Dropout(0.25)\n"
            "- Dense(512) -> Dropout(0.25)\n"
            "- Dense(256) -> Dense(6, softmax)\n"
        )
    return (
        "- MLP input: trace length 1551\n"
        "- Dense(256) -> Dense(256) -> Dense(6, softmax)\n"
    )


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Generate Phase 4 markdown report")
    parser.add_argument("--phase4-dir", default="results/phase4", help="Directory containing Phase 4 outputs")
    parser.add_argument(
        "--output",
        default="results/phase4/phase4_results_report.md",
        help="Output markdown report path",
    )
    args = parser.parse_args()

    fixed_results = load_json(os.path.join(args.phase4_dir, "fixed_key_results.json"))
    variable_results = load_json(os.path.join(args.phase4_dir, "variable_key_results.json"))
    fixed_history = load_json(os.path.join(args.phase4_dir, "fixed_key_history.json"))
    variable_history = load_json(os.path.join(args.phase4_dir, "variable_key_history.json"))

    fixed_model = fixed_results.get("model", "cnn")
    variable_model = variable_results.get("model", "cnn")

    lines = []
    lines.append("# Phase 4: Deep Learning Attack Results and Analysis")
    lines.append("")
    lines.append(f"- Generated (UTC): {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"- Fixed-key dataset: `{fixed_results.get('scenario', 'fixed-key')}`")
    lines.append(f"- Variable-key dataset: `{variable_results.get('scenario', 'variable-key')}`")
    lines.append("")
    lines.append("## 1. Target Variable and Leakage Labels")
    lines.append("- Target variable: key byte at `target_byte = 0`.")
    lines.append("- Label definition: Hamming weight class (0..5) of ASCON 5-bit S-box output from first-round initialization leakage.")
    lines.append("- Number of classes: 6.")
    lines.append("")
    lines.append("## 2. Model Architecture and Training Details")
    lines.append("### Fixed-Key Attack Model")
    lines.append(f"- Model type: `{fixed_model.upper()}`")
    lines.append(model_architecture_text(fixed_model, variable_key=False))
    lines.append(
        f"- Training summary: epochs={fixed_history['epochs_trained']}, "
        f"final val accuracy={fixed_results['final_val_acc']:.4f}, "
        f"final val loss={fixed_results['final_val_loss']:.4f}"
    )
    lines.append("")
    lines.append("### Variable-Key Attack Model")
    lines.append(f"- Model type: `{variable_model.upper()}`")
    lines.append(model_architecture_text(variable_model, variable_key=True))
    lines.append(
        f"- Training summary: epochs={variable_history['epochs_trained']}, "
        f"final val accuracy={variable_results['final_val_acc']:.4f}, "
        f"final val loss={variable_results['final_val_loss']:.4f}"
    )
    lines.append("")
    lines.append("## 3. Attack Performance (Fixed vs Variable Key)")
    lines.append("| Scenario | Model | Success Rate (rank=0) | Mean Rank | Guessing Entropy (bits) |")
    lines.append("|---|---|---:|---:|---:|")
    lines.append(
        f"| Fixed-key | {fixed_model.upper()} | {fixed_results['success_rate']:.4f} | "
        f"{fixed_results['rank']:.2f} | {fixed_results.get('guessing_entropy_bits', 0.0):.4f} |"
    )
    lines.append(
        f"| Variable-key | {variable_model.upper()} | {variable_results['success_rate_rank0']:.4f} | "
        f"{variable_results['mean_rank']:.2f} | {variable_results.get('guessing_entropy_bits', 0.0):.4f} |"
    )
    lines.append("")
    lines.append("## 4. Key Recovery Results")
    lines.append(f"- Fixed-key rank of true key byte: **{fixed_results['rank']}** (0 means fully recovered).")
    lines.append(f"- Fixed-key true key-byte value: `0x{int(fixed_results['true_key']):02x}`.")
    lines.append(
        f"- Variable-key rank statistics: mean={variable_results['mean_rank']:.2f}, "
        f"median={variable_results['median_rank']:.2f}, std={variable_results['std_rank']:.2f}."
    )
    lines.append(
        f"- Variable-key success rates: rank-0={variable_results['success_rate_rank0']:.4f}, "
        f"rank<=5={variable_results['success_rate_rank5']:.4f}, rank<=10={variable_results['success_rate_rank10']:.4f}."
    )
    lines.append("")
    lines.append("## 5. Critical Analysis and Observations")
    lines.append("- Fixed-key attack is expected to perform better because profiling and attack share the same secret key structure.")
    lines.append("- Variable-key attack is harder because the model must generalize leakage behavior across unseen keys, not only unseen nonces.")
    lines.append("- The fixed-key rank result indicates recoverability of the target byte under the selected leakage point and trace window.")
    lines.append("- Variable-key mean rank and rank-0 rate quantify the current generalization gap.")
    lines.append("- Limitation: only one target byte and one leakage point (`target_byte=0`, first-round init slice) were attacked.")
    lines.append("- Limitation: training uses a single split per dataset; repeated runs and confidence intervals would improve robustness.")
    lines.append("")
    lines.append("## 6. Output Artifacts")
    lines.append("- `scripts/attack_fixed_key.py`")
    lines.append("- `scripts/attack_variable_key.py`")
    lines.append("- `results/phase4/model_fixed_key.h5`")
    lines.append("- `results/phase4/model_variable_key.h5`")
    lines.append("- `results/phase4/fixed_key_results.json`")
    lines.append("- `results/phase4/variable_key_results.json`")
    lines.append("- `results/phase4/fixed_key_training_curves.png`")
    lines.append("- `results/phase4/variable_key_training_curves.png`")
    lines.append("- `results/phase4/fixed_key_key_scores.png`")
    lines.append("- `results/phase4/variable_key_rank_hist.png`")

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Phase 4 report written to: {args.output}")


if __name__ == "__main__":
    main()

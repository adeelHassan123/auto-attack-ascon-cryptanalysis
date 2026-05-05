# Phase 3 Dataset Documentation

## Trace Generation Process
- Traces generated from ARM ELF using Rainbow emulation (Cortex-M3).
- Dataset file: `data/datasets/fixed_key_dataset.h5`
- Scenario: fixed-key
- Number of traces: 20000
- Max instructions per trace: 3000
- Stored samples per trace: 1500
- Synthetic traces used: 0

## Leakage Model
- Trace leakage source: Rainbow register Hamming Weight events.
- Label leakage model: ASCON S-box output Hamming Weight (5-bit -> classes 0..5).

## Target Value Selection
- Target byte index: 0
- Target label computed from the ASCON intermediate S-box-related state for the chosen byte.

## Validation Summary
- HW class counts: [632, 3108, 6186, 6301, 3139, 634]
- Variable-key disjoint profiling/attack keys: True

## Sample Trace Plots
- Plot directory: `results/phase3/fixed_plots`
- Includes at least 10 individual traces plus one overlay plot.

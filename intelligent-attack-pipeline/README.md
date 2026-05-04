# Intelligent Attack Pipeline

Side-channel analysis framework for attacking ASCON-128 using deep learning (MLP and CNN comparison).

## Project Structure

```
intelligent-attack-pipeline/
├── src/                          # Source code modules
│   ├── __init__.py
│   ├── models/                   # Neural network architectures
│   │   ├── __init__.py
│   │   ├── mlp.py               # Multi-Layer Perceptron
│   │   └── cnn.py               # Convolutional Neural Network
│   ├── attacks/                  # Attack implementations
│   │   ├── __init__.py
│   │   └── key_recovery.py      # Key recovery algorithms
│   ├── dataset/                  # Dataset generation
│   │   ├── __init__.py
│   │   └── generator.py         # ASCAD-like dataset generator
│   └── utils/                    # Utility functions
│       ├── __init__.py
│       └── metrics.py            # Hamming weight, etc.
├── scripts/                      # Execution scripts
│   ├── run_attack.py            # Run single attack experiment
│   └── compare_models.py        # Compare MLP vs CNN
├── config/                     # Configuration files
│   └── attack_config.yaml       # Attack parameters
├── phase_2/                    # ASCON-128 C implementation
│   └── ascon128-c/
│       ├── inc/
│       ├── src/
│       ├── tests/
│       └── Makefile
├── data/                       # Generated datasets
│   └── datasets/
├── results/                    # Output results
│   ├── models/                 # Trained models (.h5)
│   ├── plots/                  # Visualization plots
│   └── logs/                   # Execution logs
├── tests/                      # Unit tests
└── docs/                       # Documentation
```

## Quick Start

### 1. Generate Datasets

```bash
cd intelligent-attack-pipeline
python -m src.dataset.generator
```

### 2. Run Attack (MLP)

```bash
python scripts/run_attack.py --model mlp --dataset data/datasets/fixed_key_dataset.h5
```

### 3. Run Attack (CNN)

```bash
python scripts/run_attack.py --model cnn --dataset data/datasets/fixed_key_dataset.h5
```

### 4. Compare Models

```bash
python scripts/compare_models.py --dataset data/datasets/fixed_key_dataset.h5
```

## Phase 2: ASCON-128 Implementation

See `phase_2/ascon128-c/` for the C implementation:

```bash
cd phase_2/ascon128-c
make all      # Build library
make test     # Run tests
make arm      # Compile for ARM Cortex-M3 (requires arm-none-eabi-gcc)
```

## Requirements

- Python 3.8+
- TensorFlow 2.x
- NumPy, h5py, scikit-learn, matplotlib, pandas
- ARM GCC (for embedded compilation)

## Attack Scenarios

- **Fixed-Key**: Single secret key, multiple plaintexts
- **Variable-Key**: Unique key per trace (harder scenario)

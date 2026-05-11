# ASCON-128 Side-Channel Analysis

Verified ASCON-128 side-channel attack implementation with Rainbow emulation.


## Quick Start

### 1. Verify C Implementation

```bash
cd phase_2/ascon128-c
make clean
make verify
```

**Expected:** Both NIST tests PASS

### 2. Build ARM Binary

```bash
make arm
ls -la build/ascon128.elf
```

### 3. Python Pipeline

```bash
cd intelligent-attack-pipeline
python3 -c "from src.utils.metrics_fixed import compute_ascon_sbox_hw; print('OK')"
```

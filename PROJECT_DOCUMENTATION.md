# ASCON-128 Deep Learning Side-Channel Analysis System

## Complete Technical Documentation for NIST Lightweight Cipher Cryptanalysis

---

# 1. Project Overview

## 1.1 What Is This Project?

The **ASCON-128 Deep Learning Side-Channel Analysis System** is a comprehensive, research-grade framework for performing power analysis attacks against the NIST-standardized ASCON lightweight authenticated encryption cipher. This project implements the complete cryptanalysis pipeline: from ASCON-128 implementation in C for ARM architecture, through power trace generation using the Rainbow emulation framework, to deep learning-based key recovery using both Multi-Layer Perceptron (MLP) and Convolutional Neural Network (CNN) architectures with comparative analysis.

### Real-World Analogy

Imagine a high-security vault with a sophisticated combination lock. While the lock's mathematical mechanism is theoretically unbreakable, a skilled attacker can place sensors on the vault door to detect tiny vibrations when internal gears engage. Each vibration pattern correlates with specific internal states. Similarly, this project analyzes the "vibrations" (power consumption) of an ASCON-128 implementation running on an ARM processor. Every time the ASCON S-box processes data, the power consumption reveals information about the secret key. By training neural networks to recognize these patterns across thousands of encryptions, the system can recover the 128-bit secret key without mathematically breaking the cipher.

### Problem It Solves

ASCON-128 was selected by NIST in 2023 as the standard for lightweight cryptography in IoT and embedded devices. While mathematically secure, its implementations can leak information through power consumption during cryptographic operations. This project:
- **Implements** ASCON-128 from specification to ARM binary for realistic analysis
- **Simulates** power traces using the Rainbow framework without expensive hardware
- **Trains** both MLP and CNN models to classify S-box Hamming Weight leakage
- **Compares** deep learning architectures for optimal attack performance
- **Recovers** secret keys from ASCON-128 implementations via side-channel analysis
- **Provides** a complete research platform for ASCON security evaluation

### Target Users

- **Cybersecurity Researchers**: Studying ASCON-128 side-channel vulnerabilities
- **Cryptography Students**: Learning sponge construction and S-box leakage analysis
- **Hardware Security Engineers**: Evaluating ASCON implementations on embedded devices
- **IoT Security Professionals**: Assessing lightweight cipher security
- **Academic Institutions**: Teaching advanced side-channel cryptanalysis techniques

---

# 2. Purpose & Motivation

## 2.1 Why This Project Exists

### Background Context

In 2023, NIST selected ASCON as the standard for lightweight cryptography, specifically designed for resource-constrained IoT devices. ASCON uses a **sponge construction** with a 320-bit internal state (5 × 64-bit words) and provides authenticated encryption with associated data (AEAD). Despite its strong theoretical security, ASCON implementations—like all cryptographic implementations—can leak information through side channels.

**ASCON-128 Structure**:
- **Key Size**: 128 bits
- **Nonce Size**: 128 bits
- **Internal State**: 320 bits (5 × 64-bit words: x0, x1, x2, x3, x4)
- **Security Level**: 128-bit classical security
- **Construction**: Sponge-based permutation with 12-round initialization/finalization (p12) and 6-round intermediate processing (p6)

**Side-Channel Vulnerability**:
The ASCON substitution layer (S-box) is the primary leakage point. This 5-bit S-box operates on each bit-slice of the 5 state words simultaneously, providing non-linearity that creates data-dependent power consumption. By analyzing power traces during S-box operations, attackers can recover information about the secret key.

### Problems in Existing Systems

| Problem | Impact | Solution This Project Provides |
|---------|--------|-------------------------------|
| ASCON-128 side-channel vulnerability assessment | NIST standard needs security validation | Complete ASCON implementation with S-box leakage analysis |
| Expensive hardware required for trace collection | Limits research accessibility | Rainbow framework simulation without oscilloscopes |
| No standardized ASCON SCA datasets | Fragmented research results | ASCAD-compatible HDF5 dataset generation |
| Unclear which DL architecture is best for ASCON | Suboptimal attack performance | MLP vs CNN comparative analysis |
| Manual analysis is time-consuming and error-prone | Slow attack execution | Automated neural network-based key recovery |
| Fixed-key scenarios don't reflect real-world threats | Limited attack generalization | Variable-key training with unique keys per trace |
| Lack of integrated ASCON analysis toolchain | Fragmented research workflow | Unified pipeline: implementation → traces → attack |

### How This Project Improves Upon Existing Solutions

1. **Complete ASCON-128 Implementation**: Full C implementation from NIST specification, compiled for ARM Cortex-M3, not simplified XOR
2. **Rainbow Framework Integration**: Uses Ledger's side-channel analysis tool for realistic power trace simulation
3. **Dual Neural Network Comparison**: Systematic comparison of MLP vs CNN for ASCON S-box leakage classification
4. **NIST-Standard Target**: Focuses on the latest NIST lightweight cryptography standard (2023)
5. **S-box Specific Leakage**: Targets the 5-bit ASCON S-box output (HW 0-5) rather than generic operations
6. **Sponge Construction Analysis**: Analyzes 320-bit state operations with 5 × 64-bit word representation

### Significance and Impact

- **Academic**: First comprehensive ASCON-128 side-channel analysis framework for educational and research use
- **Industrial**: Enables pre-deployment security validation of IoT devices using NIST-standard cryptography
- **Standardization**: Supports NIST's lightweight cryptography standard security evaluation
- **Methodological**: Provides benchmark comparison of MLP vs CNN for sponge construction ciphers
- **Security**: Helps identify ASCON vulnerabilities before widespread IoT deployment

---

# 3. Objectives

## 3.1 Functional Objectives

### Phase 1: Research and Understanding
- **FO-1.1**: Analyze ASCON-128 AEAD specification and sponge construction
- **FO-1.2**: Identify S-box as primary side-channel leakage point
- **FO-1.3**: Study 320-bit state representation (5 × 64-bit words: x0, x1, x2, x3, x4)
- **FO-1.4**: Document 12-round permutation (p12) structure

### Phase 2: Implementation
- **FO-2.1**: Implement ASCON-128 in C with core data structures
- **FO-2.2**: Implement p12() permutation with three layers:
  - Add Round Constants (ARC)
  - S-box Layer (sbox_layer) - 5-bit substitution
  - Linear Diffusion Layer (linear_layer)
- **FO-2.3**: Implement AEAD API: ascon_init(), ascon_process_ad(), ascon_encrypt(), ascon_finalize()
- **FO-2.4**: Compile for ARM Cortex-M3 architecture producing ascon128.elf

### Phase 3: Trace Generation
- **FO-3.1**: Set up Rainbow framework emulator for ARM binary
- **FO-3.2**: Implement Hamming Weight leakage model targeting S-box output
- **FO-3.3**: Create trace generation loop with Rainbow/Unicorn emulation
- **FO-3.4**: Generate Fixed-Key dataset (70% profiling, 30% attack)
- **FO-3.5**: Generate Variable-Key dataset (unique key per trace)
- **FO-3.6**: Store in HDF5 format with ASCAD-compatible structure

### Phase 4: Deep Learning Attack with MLP vs CNN Comparison
- **FO-4.1**: **MLP Architecture**: Implement Multi-Layer Perceptron with dense layers
- **FO-4.2**: **CNN Architecture**: Implement 1D Convolutional Neural Network with Conv1D layers
- **FO-4.3**: Train both architectures on Fixed-Key dataset
- **FO-4.4**: Train both architectures on Variable-Key dataset
- **FO-4.5**: Compare performance metrics: accuracy, loss, training time
- **FO-4.6**: Perform key recovery using both models
- **FO-4.7**: Generate comparative analysis report (MLP vs CNN)

### Phase 5: Attack Execution
- **FO-5.1**: Implement key rank analysis algorithm
- **FO-5.2**: Execute attacks on Fixed-Key scenario with both models
- **FO-5.3**: Execute attacks on Variable-Key scenario with both models
- **FO-5.4**: Calculate guessing entropy and success rates
- **FO-5.5**: Generate visualization plots (training curves, rank evolution)

## 3.2 Non-Functional Objectives

| Objective | Target | Measurement |
|-----------|--------|-------------|
| ASCON Implementation | Correct permutation p12() execution | Test vectors validation |
| ARM Compilation | Successful ascon128.elf generation | File format verification |
| Trace Generation | 60,000 traces in <10 minutes | Execution time benchmark |
| MLP Training | Convergence within 50-75 epochs | Loss < 0.5, Accuracy > 50% |
| CNN Training | Convergence within 50 epochs | Comparable or better than MLP |
| Fixed-Key Attack | Success rate >90% | Key rank evaluation |
| Variable-Key Attack | Success rate >20% | Cross-key validation |
| MLP vs CNN Comparison | Quantitative metrics for both | Accuracy, loss, time, success rate comparison table |
| Dataset Compatibility | ASCAD HDF5 format | h5py structure validation |

- **Academic**: Supports research into next-generation cryptographic countermeasures
- **Industrial**: Enables pre-deployment security validation of embedded systems
- **Educational**: Democratizes access to advanced cryptanalysis training
- **Security**: Helps identify vulnerabilities before malicious actors exploit them

---

# 4. Key Features (Detailed)

## 4.1 Feature 1: ASCON-128 Implementation

### What It Does

Implements the complete ASCON-128 authenticated encryption algorithm from the NIST specification in C, compiled for ARM Cortex-M3 architecture. This includes the 320-bit sponge construction with 5 × 64-bit word state representation and the 12-round permutation (p12).

### Why It Exists

To perform realistic side-channel analysis against the NIST-standardized lightweight cipher. Unlike simplified XOR ciphers used for teaching, this implementation:
- Uses the actual sponge construction with proper permutation rounds
- Implements the 5-bit S-box that creates non-linear leakage
- Targets the initialization phase where secret key and nonce interact
- Provides research-grade target for ASCON security evaluation

### How It Works Internally

```c
// ASCON State Structure (320 bits)
typedef struct {
    uint64_t x0, x1, x2, x3, x4;  // 5 × 64-bit words
} ascon_state_t;

// Initialization: x0=IV, x1-x2=Key, x3-x4=Nonce
void ascon_init(ascon_state_t *s, const uint8_t *key, const uint8_t *nonce);

// 12-Round Permutation p12()
void p12(ascon_state_t *s) {
    for (int round = 0; round < 12; round++) {
        add_round_constant(s, round);   // ARC
        sbox_layer(s);                   // 5-bit S-box (LEAKAGE POINT)
        linear_layer(s);                 // Linear diffusion
    }
}

// S-Box Layer: 5-bit substitution applied to 64 bit-slices
void sbox_layer(ascon_state_t *s) {
    // S-box operates on columns: x0[i], x1[i], x2[i], x3[i], x4[i]
    // Creates non-linear transformation: leakage source
}
```

**State Evolution**:
```
Initial State (320 bits):
┌─────────┬─────────┬─────────┬─────────┬─────────┐
│   x0    │   x1    │   x2    │   x3    │   x4    │
│  (IV)   │Key[0:63]│Key[64:] │Nonce[0] │Nonce[1] │
└─────────┴─────────┴─────────┴─────────┴─────────┘
                    ↓ p12() - 12 rounds
Final State: Authentication tag extracted
```

## 4.2 Feature 2: Rainbow Framework Trace Generation

### What It Does

Uses Ledger's Rainbow framework (built on Unicorn CPU emulator) to execute the ARM-compiled ASCON binary and generate synthetic power traces based on the Hamming Weight leakage model.

### Why It Exists

Physical power analysis requires expensive oscilloscopes, probes, and cryptographic hardware. Rainbow simulation provides:
- Cost-effective ASCON security research without hardware
- Perfectly reproducible experiments for validation
- Instruction-level power consumption observation
- Safe testing environment for attack development

### How It Works Internally

```python
# Rainbow Trace Generation Workflow
import rainbow
from rainbow.generics import rainbow_arm

# 1. Load ARM binary
emu = rainbow_arm(trace_config=TraceConfig(register=HammingWeight()))
emu.load('ascon128.elf', typ='elf')

# 2. Configure memory regions
RAM_BASE = 0x20000000
emu.emu.mem_map(RAM_BASE, 0x100000)

# 3. Trace Generation Loop
for i in range(num_traces):
    # Generate random plaintext and key
    plaintext = os.urandom(16)
    key = fixed_key if fixed_mode else os.urandom(16)
    
    # Write to emulator memory
    emu.emu.mem_write(PLAINTEXT_ADDR, plaintext)
    emu.emu.mem_write(KEY_ADDR, key)
    
    # Execute ASCON encryption
    emu.start(function_addr, end_addr)
    
    # Extract power trace from S-box operations
    trace = [point.get('register', 0) for point in emu.trace]
    
    # Target: S-box output Hamming Weight (0-5)
    label = calculate_sbox_hw(plaintext, key)
```

**Leakage Model**:
```
Power Leakage Target: S-box Output (First Round)
Label = HW(S-box_output) where HW ∈ {0, 1, 2, 3, 4, 5}

Why S-box? Non-linear operation creates data-dependent power:
- Input: 5-bit column from state words (x0-x4)
- Output: 5-bit transformed value
- Power ∝ number of '1' bits in output
```

## 4.3 Feature 3: MLP vs CNN Architecture Comparison

### Overview

This project implements and compares two deep learning architectures for ASCON S-box leakage classification:
1. **Multi-Layer Perceptron (MLP)**: Dense feedforward neural network
2. **Convolutional Neural Network (CNN)**: 1D convolutional architecture

### MLP Architecture (Dense Layers)

**Structure**:
```
Input: (trace_length, ) → 1551 power samples
┌─────────────────────────────────────────────┐
│ Dense(512/256, ReLU)                        │
│ Dropout(0.25) [Variable-key only]          │
├─────────────────────────────────────────────┤
│ Dense(512/256, ReLU)                        │
│ Dropout(0.25) [Variable-key only]          │
├─────────────────────────────────────────────┤
│ Dense(256, ReLU) [Variable-key only]        │
├─────────────────────────────────────────────┤
│ Dense(6, Softmax) ← HW classes 0-5        │
└─────────────────────────────────────────────┘
```

**Characteristics**:
- Fully connected layers learn global trace patterns
- Simpler architecture, faster training
- Good baseline for comparison
- May overfit on fixed-key scenarios

### CNN Architecture (Convolutional)

**Structure**:
```
Input: (trace_length, 1) → (1551, 1) reshaped
┌─────────────────────────────────────────────┐
│ Conv1D(64 filters, kernel=10, ReLU)         │
│ AveragePooling1D(pool_size=5)               │
├─────────────────────────────────────────────┤
│ Conv1D(128 filters, kernel=5, ReLU)         │
├─────────────────────────────────────────────┤
│ Flatten()                                   │
├─────────────────────────────────────────────┤
│ Dense(256, ReLU)                            │
├─────────────────────────────────────────────┤
│ Dense(6, Softmax) ← HW classes 0-5        │
└─────────────────────────────────────────────┘
```

**Characteristics**:
- Convolutional layers extract local temporal features
- Better at identifying specific leakage patterns in traces
- More robust to trace misalignment
- Generally better generalization for variable-key attacks

### Comparison Metrics

| Metric | MLP | CNN | Purpose |
|--------|-----|-----|---------|
| Training Accuracy | Compare | Compare | Learning effectiveness |
| Validation Accuracy | Compare | Compare | Generalization |
| Training Time | Measure | Measure | Efficiency |
| Convergence Epochs | Count | Count | Training speed |
| Fixed-Key Success Rate | % | % | Attack effectiveness |
| Variable-Key Success Rate | % | % | Generalization ability |
| Key Rank (Mean) | Value | Value | Attack quality |

## 4.4 Feature 4: Dual Dataset Modes

### Fixed-Key Dataset (70/30 Split)

**Configuration**:
- **Profiling**: 70% of traces (42,000) with random plaintexts, single fixed 128-bit key
- **Attack**: 30% of traces (18,000) with different plaintexts, same fixed key

**Purpose**: Template attack scenario—train on known key, attack same key

**Expected Performance**:
- MLP: High accuracy (60-80%), fast convergence
- CNN: High accuracy (65-85%), feature extraction benefits

### Variable-Key Dataset (Unique Key Per Trace)

**Configuration**:
- **Profiling**: 50,000 traces with random plaintexts AND unique random keys per trace
- **Attack**: 10,000 traces with never-before-seen keys

**Purpose**: Profiling attack scenario—test model generalization across all possible keys

**Expected Performance**:
- MLP: Moderate success (20-40%), may overfit
- CNN: Better success (25-45%), convolutional generalization

## 4.5 Feature 5: ASCON S-Box Key Recovery

### Attack Algorithm

```python
def ascon_key_recovery(predictions, plaintexts, true_key_byte):
    """
    ASCON-specific key recovery using S-box leakage
    Target: First round S-box output during initialization
    """
    key_scores = np.zeros(256)
    
    for key_guess in range(256):
        for trace_idx in range(num_traces):
            pt = plaintexts[trace_idx, target_byte]
            
            # ASCON S-box operation (simplified)
            # In real attack: proper ASCON state initialization
            intermediate = pt ^ key_guess
            
            # ASCON uses 5-bit S-box: HW ∈ {0, 1, 2, 3, 4, 5}
            sbox_out = ascon_sbox(intermediate)
            hw = hamming_weight_5bit(sbox_out)
            
            # Accumulate log probability
            prob = predictions[trace_idx, hw]
            key_scores[key_guess] += np.log(prob + 1e-36)
    
    # Rank: position of true key in sorted scores
    ranked_keys = np.argsort(-key_scores)
    rank = np.where(ranked_keys == true_key_byte)[0][0]
    
    return rank, key_scores
```

### Success Metrics

| Rank | Interpretation |
|------|---------------|
| 0 (1st position) | **Perfect recovery**—correct key is top guess |
| 1-10 | **Good recovery**—key in top 10 candidates |
| 11-50 | **Partial recovery**—possible with more traces |
| 51-255 | **Failed attack**—insufficient information |

### Why Both Modes Matter

| Scenario | Real-World Equivalent | Attack Strategy |
|----------|---------------------|-----------------|
| Fixed-Key | Compromised device with static key | Template attack |
| Variable-Key | Generalizable attack on any device | Profiling attack |

---

# 5. System Architecture

## 5.1 High-Level Architecture

```mermaid
flowchart TB
    subgraph "Phase 1: ASCON Implementation"
        A[ASCON-128 Spec] --> B[C Implementation]
        B --> C[ARM Compilation]
        C --> D[ascon128.elf]
    end
    
    subgraph "Phase 2: Trace Generation"
        D --> E[Rainbow Emulator]
        E --> F[ARM Cortex-M3 Execution]
        F --> G[S-box HW Extraction]
        G --> H[HDF5 Dataset Storage]
    end
    
    subgraph "Phase 3: Neural Network Training"
        H --> I[Data Loader]
        I --> J[Label Generator<br/>S-box HW 0-5]
        J --> K[MLP Trainer]
        J --> L[CNN Trainer]
        K --> M[MLP Model]
        L --> N[CNN Model]
    end
    
    subgraph "Phase 4: Attack & Comparison"
        M --> O[MLP Key Recovery]
        N --> P[CNN Key Recovery]
        O --> Q[MLP Metrics]
        P --> R[CNN Metrics]
        Q --> S[Comparative Analysis]
        R --> S
    end
    
    subgraph "Phase 5: Results"
        S --> T[Comparison Tables]
        S --> U[Training Curves]
        S --> V[Rank Distributions]
    end
```

## 5.2 Component Interactions

| Component | Input | Output | Responsibility |
|-----------|-------|--------|----------------|
| ASCON Implementation | Key, Nonce, Plaintext | Ciphertext, Tag | NIST-standard cipher execution |
| Rainbow Emulator | ascon128.elf | Instruction trace | ARM execution simulation |
| HW Extractor | Register values | HW labels 0-5 | S-box leakage calculation |
| HDF5 Storage | Traces, labels, metadata | .h5 files | ASCAD-compatible dataset |
| MLP Trainer | Traces, labels | Dense model | Baseline neural network |
| CNN Trainer | Reshaped traces, labels | Conv1D model | Feature extraction network |
| Key Rank Analyzer | Predictions, PT/Key | Rank, Success Rate | Key recovery for both models |
| Comparative Visualizer | Both model metrics | Plots, tables | MLP vs CNN comparison |

### Algorithm

```python
# For each key guess k in [0, 255]:
score[k] = Σ log(probability_model[trace_i, HW(plaintext_i ⊕ k)])

# Rank is position of correct key in sorted scores
rank = position of true_key in argsort(-score)
```

---

# 6. Technology Stack

## 6.1 Core Technologies

| Technology | Version | Purpose | Why Selected |
|------------|---------|---------|--------------|
| Python | 3.8+ | Primary language | Rich ecosystem for ML and crypto |
| NumPy | 1.20+ | Numerical computing | Efficient 320-bit state operations |
| HDF5 (h5py) | 3.0+ | Dataset storage | ASCAD standard for SCA datasets |
| TensorFlow/Keras | 2.10+ | Deep learning | MLP and CNN implementation |
| scikit-learn | 1.0+ | Data splitting | Stratified sampling for HW 0-5 classes |
| pandas | 1.3+ | Data analysis | MLP vs CNN comparison tables |
| matplotlib | 3.5+ | Visualization | Training curve and rank distribution plots |

## 6.2 ASCON & Emulation Components

| Component | Purpose | Role in Pipeline |
|-----------|---------|------------------|
| GCC ARM None EABI | Cross-compilation for ARM Cortex-M3 | Compiles ascon128.c to .elf |
| Rainbow Framework | Side-channel analysis simulation | Emulates ARM execution, generates traces |
| Unicorn Engine | CPU emulator (ARM) | Underlying emulation engine |
| Lief | Binary instrumentation | ELF parsing and manipulation |
| ascon128.c | ASCON-128 implementation | Target cryptographic algorithm |
| ascon128.elf | Compiled ARM binary | Emulation target for Rainbow |

## 6.3 Why This Stack for ASCON?

1. **Rainbow + Unicorn**: Industry-standard combination for side-channel simulation without hardware
2. **TensorFlow**: Supports both MLP (Dense layers) and CNN (Conv1D layers) in unified framework
3. **HDF5**: ASCAD-compatible format enables interoperability with existing ASCON research
4. **ARM GCC**: Produces realistic embedded target binaries for IoT security research
5. **NumPy**: Efficiently handles 320-bit ASCON state as 5 × uint64 arrays

---

# 7. Project Structure

## 7.1 Repository Layout

```
intelligent-attack-pipeline/
├── ascon128.c                   # ASCON-128 C implementation
├── ascon128.elf                 # Compiled ARM binary (generated)
├── flash.ld                     # ARM linker script
├── generate_traces.py           # Rainbow-based trace generation
├── attack_fixed_key.py          # Fixed-key attack with MLP/CNN
├── attack_variable_key.py       # Variable-key attack with MLP/CNN
├── comparative_analysis.py      # MLP vs CNN comparison
├── model_fixed_key_mlp.h5       # Trained MLP model (generated)
├── model_fixed_key_cnn.h5       # Trained CNN model (generated)
├── model_variable_key_mlp.h5    # Variable-key MLP model (generated)
├── model_variable_key_cnn.h5    # Variable-key CNN model (generated)
├── docs/
│   ├── COMPLETE-DOC.MD         # Lab documentation
│   ├── ROADMAP.MD              # ASCON project roadmap
│   └── PROJECT_DOCUMENTATION.md # This file
├── datasets/                    # Generated HDF5 datasets
│   ├── fixed_key_dataset.h5
│   └── variable_key_dataset.h5
└── results/                     # Generated outputs
    ├── training_curves_mlp.png
    ├── training_curves_cnn.png
    ├── rank_distribution_mlp.png
    ├── rank_distribution_cnn.png
    └── comparison_table.csv
```

## 7.2 File Responsibilities

### `ascon128.c`

**Lines of Code**: ~200-300 (estimated)

**Components**:
- `ascon_state_t`: 320-bit state structure (5 × uint64_t)
- `ascon_init()`: Initialize state with IV, Key, Nonce
- `p12()`: 12-round permutation (ARC + S-box + Linear)
- `sbox_layer()`: 5-bit substitution (leakage source)
- `linear_layer()`: Cyclic shifts for diffusion
- `ascon_encrypt()`: AEAD encryption function
- `ascon_finalize()`: Authentication tag generation

**Key Data Structure**:
```c
typedef struct {
    uint64_t x0;  // IV (64 bits)
    uint64_t x1;  // Key[0:63]
    uint64_t x2;  // Key[64:127]
    uint64_t x3;  // Nonce[0:63]
    uint64_t x4;  // Nonce[64:127]
} ascon_state_t;  // Total: 320 bits
```

### `generate_traces.py`

**Purpose**: Rainbow-based trace generation for ASCON

**Core Functions**:
- `setup_emulator()`: Initialize Rainbow ARM emulator
- `generate_ascon_trace()`: Single trace generation with S-box HW extraction
- `create_dataset()`: HDF5 dataset creation (fixed/variable key)

**Workflow**:
1. Load `ascon128.elf` into Rainbow emulator
2. Map ARM memory regions (RAM_BASE = 0x20000000)
3. For each trace:
   - Generate random plaintext (16 bytes)
   - Generate key (fixed or random)
   - Execute ASCON encryption in emulator
   - Extract S-box output Hamming Weight (0-5)
   - Record power trace
4. Save to HDF5 with ASCAD structure

### `attack_fixed_key.py` & `attack_variable_key.py`

**Purpose**: Train MLP and CNN models, perform key recovery

**Core Functions**:
- `build_mlp_model()`: Dense layer architecture
- `build_cnn_model()`: Conv1D layer architecture
- `generate_sbox_labels()`: ASCON S-box HW labels (0-5)
- `train_model()`: Training with validation
- `key_recovery()`: Log-likelihood key ranking
- `evaluate_attack()`: Success rate calculation

**MLP Architecture**:
```python
model = Sequential([
    Dense(256, activation='relu', input_shape=(trace_length,)),
    Dense(256, activation='relu'),
    Dense(6, activation='softmax')  # HW 0-5
])
```

**CNN Architecture**:
```python
model = Sequential([
    Conv1D(64, 10, activation='relu', input_shape=(trace_length, 1)),
    AveragePooling1D(5),
    Conv1D(128, 5, activation='relu'),
    Flatten(),
    Dense(256, activation='relu'),
    Dense(6, activation='softmax')  # HW 0-5
])
```

### `comparative_analysis.py`

**Purpose**: Compare MLP vs CNN performance

**Metrics Compared**:
- Training accuracy (final and per-epoch)
- Validation accuracy
- Training loss convergence
- Training time
- Attack success rate (fixed-key)
- Attack success rate (variable-key)
- Mean key rank
- Guessing entropy

---

# 8. Detailed Design

## 8.1 Module-Level Design

### ASCON Implementation Module

```
┌─────────────────────────────────────────┐
│        ASCON-128 Core Implementation     │
├─────────────────────────────────────────┤
│                                         │
│  ┌─────────────────────────────────────┐│
│  │    ascon_state_t Structure         ││
│  │  ┌─────┬─────┬─────┬─────┬─────┐ ││
│  │  │ x0  │ x1  │ x2  │ x3  │ x4  │ ││
│  │  │ IV  │ Key │ Key │Nonce│Nonce│ ││
│  │  │64bit│64bit│64bit│64bit│64bit│ ││
│  │  └─────┴─────┴─────┴─────┴─────┘ ││
│  │         Total: 320 bits            ││
│  └─────────────────────────────────────┘│
│                   │                      │
│         ┌────────┴────────┐             │
│         ▼                 ▼             │
│  ┌──────────────┐  ┌──────────────┐    │
│  │  p12() Perm  │  │  p6() Perm   │    │
│  │  12 rounds   │  │  6 rounds    │    │
│  └──────┬───────┘  └──────┬───────┘    │
│         │                 │             │
│         └────────┬────────┘             │
│                  ▼                      │
│  ┌──────────────────────────────────┐ │
│  │    Round Structure (per round):    │ │
│  │  1. Add Round Constant (ARC)     │ │
│  │  2. S-box Layer (5-bit, 64×)    │ │ ← LEAKAGE POINT
│  │  3. Linear Diffusion Layer       │ │
│  └──────────────────────────────────┘ │
│                  │                      │
│         ┌────────┴────────┐             │
│         ▼                 ▼             │
│  ┌──────────────┐  ┌──────────────┐    │
│  │ Ciphertext   │  │   Tag (128)  │    │
│  └──────────────┘  └──────────────┘    │
└─────────────────────────────────────────┘
```

### Rainbow Trace Generation Module

```
┌─────────────────────────────────────────┐
│      ASCON Trace Generation Flow       │
├─────────────────────────────────────────┤
│                                         │
│  Input: ascon128.elf, num_traces        │
│                                         │
│  ┌──────────────────────────────────┐  │
│  │ Rainbow ARM Emulator Setup       │  │
│  │ - Load ELF binary                │  │
│  │ - Map memory 0x20000000          │  │
│  │ - Configure trace registers      │  │
│  └──────────────┬───────────────────┘  │
│                 │                       │
│  ┌──────────────┴───────────────────┐  │
│  │    Trace Generation Loop          │  │
│  │                                   │  │
│  │  for i in range(num_traces):     │  │
│  │    ├─ Generate random PT (16B)    │  │
│  │    ├─ Generate Key (fixed/var)  │  │
│  │    ├─ Write PT/Key to RAM       │  │
│  │    ├─ emu.start(ascon_encrypt)  │  │
│  │    ├─ Extract register trace    │  │
│  │    └─ Calculate S-box HW (0-5)  │  │
│  │                                   │  │
│  └──────────────┬───────────────────┘  │
│                 │                       │
│  ┌──────────────┴───────────────────┐  │
│  │    HDF5 Output (ASCAD format)     │  │
│  │  /Profiling_traces/traces[n,1551] │  │
│  │  /Profiling_traces/metadata/      │  │
│  │    ├── plaintext[n,16]            │  │
│  │    ├── key[n,16]                  │  │
│  │    └── ciphertext[n,16]           │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

### MLP Neural Network Module

```
┌─────────────────────────────────────────┐
│       MLP Architecture (Dense Only)     │
├─────────────────────────────────────────┤
│                                         │
│  Input: (batch_size, 1551)              │
│         Flattened power trace           │
│                                         │
│  ┌─────────────────────────────────┐   │
│  │ Dense(512, ReLU)                │   │
│  │ ├─ 512 neurons                  │   │
│  │ └─ Learns global patterns       │   │
│  │ [Dropout(0.25) - variable only]│   │
│  ├─────────────────────────────────┤   │
│  │ Dense(512, ReLU)                │   │
│  │ ├─ 512 neurons                  │   │
│  │ └─ Deeper feature learning     │   │
│  │ [Dropout(0.25) - variable only]│   │
│  ├─────────────────────────────────┤   │
│  │ Dense(256, ReLU)                │   │
│  │ └─ [Variable-key models only]   │   │
│  ├─────────────────────────────────┤   │
│  │ Dense(6, Softmax)               │   │
│  │ └─ HW Classes: 0,1,2,3,4,5    │   │
│  └─────────────────────────────────┘   │
│                                         │
│  Output: (batch_size, 6)              │
│          S-box HW probabilities         │
│                                         │
└─────────────────────────────────────────┘
```

### CNN Neural Network Module

```
┌─────────────────────────────────────────┐
│    CNN Architecture (Convolutional)      │
├─────────────────────────────────────────┤
│                                         │
│  Input: (batch_size, 1551, 1)           │
│         Time-series trace data          │
│                                         │
│  ┌─────────────────────────────────┐   │
│  │ Conv1D(64, kernel=10, ReLU)      │   │
│  │ ├─ 64 filters                   │   │
│  │ ├─ Kernel size: 10 samples      │   │
│  │ └─ Extracts local temporal       │   │
│  │     leakage patterns             │   │
│  ├─────────────────────────────────┤   │
│  │ AveragePooling1D(pool=5)       │   │
│  │ └─ Downsamples by 5×             │   │
│  ├─────────────────────────────────┤   │
│  │ Conv1D(128, kernel=5, ReLU)     │   │
│  │ ├─ 128 filters                  │   │
│  │ ├─ Kernel size: 5 samples       │   │
│  │ └─ Higher-level features         │   │
│  ├─────────────────────────────────┤   │
│  │ Flatten()                      │   │
│  │ └─ Convert to 1D vector          │   │
│  ├─────────────────────────────────┤   │
│  │ Dense(256, ReLU)                 │   │
│  │ └─ Classification features       │   │
│  ├─────────────────────────────────┤   │
│  │ Dense(6, Softmax)               │   │
│  │ └─ HW Classes: 0,1,2,3,4,5    │   │
│  └─────────────────────────────────┘   │
│                                         │
│  Output: (batch_size, 6)              │
│          S-box HW probabilities         │
│                                         │
└─────────────────────────────────────────┘
```

### Key Recovery Module

```
┌─────────────────────────────────────────┐
│     ASCON Key Recovery Algorithm         │
├─────────────────────────────────────────┤
│                                         │
│  For each key guess k in [0..255]:      │
│                                         │
│    score[k] = 0                         │
│                                         │
│    For each attack trace i:             │
│      pt = plaintext[i, target_byte]     │
│      key_byte = k                       │
│                                         │
│      # ASCON state initialization       │
│      state = ascon_init(key, nonce)     │
│                                         │
│      # First round S-box output         │
│      sbox_in = state.x0 ^ state.x1      │
│      sbox_out = ASCON_SBOX(sbox_in)     │
│                                         │
│      # Hamming Weight (0-5 for 5-bit)   │
│      hw = hamming_weight(sbox_out)      │
│                                         │
│      # Model prediction                 │
│      prob = prediction[i, hw]             │
│      score[k] += log(prob + ε)          │
│                                         │
│  rank = position of true_key in         │
│         descending_sorted(score)        │
│                                         │
│  Success if rank == 0                   │
│                                         │
└─────────────────────────────────────────┘
```

## 8.2 Data Flow Diagram

```mermaid
sequenceDiagram
    participant User
    participant Generator as Dataset Generator
    participant HDF5 as HDF5 Storage
    participant Trainer as Neural Network
    participant Attacker as Key Recovery
    participant Visualizer

    User->>Generator: Configure parameters
    Generator->>Generator: Generate PT/Key pairs
    Generator->>Generator: Compute ciphertext & HW
    Generator->>Generator: Simulate power traces
    Generator->>HDF5: Write ASCAD dataset
    
    User->>Trainer: Load dataset
    HDF5->>Trainer: Read profiling traces
    Trainer->>Trainer: Generate labels
    Trainer->>Trainer: Train model
    Trainer->>HDF5: Save model weights
    
    User->>Attacker: Execute attack
    HDF5->>Attacker: Load attack traces
    Trainer->>Attacker: Load model
    Attacker->>Attacker: Generate predictions
    Attacker->>Attacker: Score all key guesses
    Attacker->>User: Return key rank
    
    User->>Visualizer: Request analysis
    Attacker->>Visualizer: Provide metrics
    Visualizer->>User: Generate plots/reports
```

## 8.3 Class/Function Responsibilities

### `ascon128.c` (ASCON Implementation)

| Function | Input | Output | Responsibility |
|----------|-------|--------|----------------|
| `ascon_init(state, key, nonce)` | 128-bit key/nonce | Initialized 320-bit state | Setup ASCON state |
| `p12(state)` | 320-bit state | Transformed state | 12-round permutation |
| `sbox_layer(state)` | 5 × 64-bit words | S-box transformed state | 5-bit substitution (leakage) |
| `linear_layer(state)` | State words | Diffused state | Cyclic shifts |
| `ascon_encrypt(state, pt, ct)` | Plaintext | Ciphertext | AEAD encryption |
| `ascon_finalize(state, tag)` | Final state | 128-bit tag | Authentication tag |

### `generate_traces.py` (Rainbow Trace Generation)

| Function | Input | Output | Responsibility |
|----------|-------|--------|----------------|
| `setup_rainbow_emulator(elf_path)` | ascon128.elf path | Emulator instance | Initialize ARM emulator |
| `generate_ascon_trace(emu, key, pt)` | Key, plaintext | Power trace | Single trace with S-box HW |
| `extract_sbox_hw(registers)` | Register values | HW 0-5 | Calculate S-box leakage |
| `create_dataset(num_traces, fixed_key)` | Configuration | HDF5 file | Dataset generation |

### `attack_fixed_key.py` & `attack_variable_key.py`

| Function | Input | Output | Responsibility |
|----------|-------|--------|----------------|
| `build_mlp_model(input_dim, num_classes)` | 1551, 6 | Keras Model | Dense layer architecture |
| `build_cnn_model(input_shape, num_classes)` | (1551,1), 6 | Keras Model | Conv1D architecture |
| `generate_sbox_labels(pt, key, target_byte)` | PT/Key arrays | HW 0-5 labels | ASCON S-box HW labels |
| `train_model(model, x_train, y_train, epochs)` | Data, config | Trained model | Model training |
| `key_recovery_ascon(predictions, pt, key_byte)` | Predictions, PT | Rank, scores | ASCON key recovery |
| `evaluate_attack(rank, true_key)` | Rank | Success/fail | Attack validation |

### `comparative_analysis.py`

| Function | Input | Output | Responsibility |
|----------|-------|--------|----------------|
| `run_mlp_experiment(dataset)` | HDF5 file | MLP metrics | Train and evaluate MLP |
| `run_cnn_experiment(dataset)` | HDF5 file | CNN metrics | Train and evaluate CNN |
| `compare_architectures(mlp_metrics, cnn_metrics)` | Both metrics | Comparison table | Side-by-side analysis |
| `plot_comparison(mlp_hist, cnn_hist)` | Training histories | PNG plots | Visualization |

---

# 9. Implementation Plan

## 9.1 Development Phases

### Phase 1: ASCON Research & Setup (Week 1)

| Task | Deliverable | Validation |
|------|-------------|------------|
| ASCON specification study | ASCON_Study_Report.pdf | Document review |
| Environment setup | Python/TensorFlow/Rainbow | Import tests |
| ARM toolchain installation | gcc-arm-none-eabi | `arm-none-eabi-gcc --version` |

### Phase 2: ASCON Implementation (Week 2)

| Task | Deliverable | Validation |
|------|-------------|------------|
| Core data structures | `ascon_state_t` with 5×uint64 | Struct size = 40 bytes |
| p12() permutation | 12-round implementation | Test vectors from spec |
| S-box layer | 5-bit substitution | Output verification |
| Linear diffusion | Cyclic shift operations | Known-answer test |
| AEAD API | ascon_init/encrypt/finalize | End-to-end encryption test |
| ARM compilation | ascon128.elf | `file ascon128.elf` shows ARM |

### Phase 3: Rainbow Trace Generation (Week 3)

| Task | Deliverable | Validation |
|------|-------------|------------|
| Rainbow emulator setup | generate_traces.py | Emulator loads ELF |
| S-box HW extraction | Leakage calculation | HW values in 0-5 range |
| Fixed-key dataset | fixed_key_dataset.h5 | 60,000 traces, 70/30 split |
| Variable-key dataset | variable_key_dataset.h5 | Unique keys verified |
| HDF5 ASCAD format | Dataset structure | h5py validation |

### Phase 4: MLP & CNN Development (Week 4)

| Task | Deliverable | Validation |
|------|-------------|------------|
| MLP architecture | attack_*_key.py with Dense layers | Model summary |
| CNN architecture | Conv1D layers implemented | Model summary |
| Fixed-key MLP training | model_fixed_key_mlp.h5 | Accuracy > 50% |
| Fixed-key CNN training | model_fixed_key_cnn.h5 | Accuracy > 50% |
| Variable-key MLP training | model_variable_key_mlp.h5 | With dropout |
| Variable-key CNN training | model_variable_key_cnn.h5 | With dropout |

### Phase 5: Attack & Comparison (Week 5)

| Task | Deliverable | Validation |
|------|-------------|------------|
| MLP key recovery | Fixed-key rank=0 | Success rate > 90% |
| CNN key recovery | Fixed-key rank=0 | Success rate > 90% |
| Variable-key MLP attack | Mean rank calculated | Success rate > 20% |
| Variable-key CNN attack | Mean rank calculated | Success rate > 20% |
| Comparative analysis | comparison_table.csv | MLP vs CNN metrics |
| Visualization | Training curves, rank dist | PNG outputs |
| Final documentation | Final_Report.pdf | Complete coverage |

## 9.2 Milestones

| Milestone | Criteria | Target Date |
|-----------|----------|-------------|
| M1: ASCON Implementation | ascon128.c compiles to ARM ELF | Week 2 |
| M2: Rainbow Trace Generation | 60,000 ASCON traces in <10 min | Week 3 |
| M3: MLP Training | Training accuracy >50% | Week 4 |
| M4: CNN Training | Training accuracy >50% | Week 4 |
| M5: Fixed-Key Attack | MLP and CNN rank=0 achieved | Week 5 |
| M6: Variable-Key Attack | Both models success rate >20% | Week 5 |
| M7: MLP vs CNN Comparison | Quantitative comparison report | Week 5 |

---

# 10. Execution Flow

## 10.1 Step-by-Step Runtime Flow

### Step 1: ASCON Implementation & Compilation

```bash
# Implement ascon128.c with 320-bit state and p12() permutation
# Then compile for ARM Cortex-M3

arm-none-eabi-gcc -mcpu=cortex-m3 -mthumb -Wall -g -O2 \
    -c ascon128.c -o ascon128.o
arm-none-eabi-gcc -mcpu=cortex-m3 -mthumb -nostdlib \
    -T flash.ld ascon128.o -o ascon128.elf

# Verify ARM binary
file ascon128.elf
# Output: ascon128.elf: ELF 32-bit LSB executable, ARM, EABI5
```

### Step 2: Rainbow-Based Trace Generation

```bash
python generate_traces.py
```

**Internal Execution**:

```python
# 1. Setup Rainbow ARM emulator
emu = rainbow_arm(trace_config=TraceConfig(register=HammingWeight()))
emu.load('ascon128.elf', typ='elf')

# 2. Map ARM memory
RAM_BASE = 0x20000000
emu.emu.mem_map(RAM_BASE, 0x100000)

# 3. Fixed-Key Dataset Generation (70/30 split)
for i in range(60000):
    # Generate random plaintext
    plaintext = os.urandom(16)
    
    # Use fixed key for all traces
    key = FIXED_KEY
    
    # Execute ASCON in emulator
    emu.emu.mem_write(PT_ADDR, plaintext)
    emu.emu.mem_write(KEY_ADDR, key)
    emu.start(ascon_encrypt_addr, end_addr)
    
    # Extract power trace
    trace = [point.get('register', 0) for point in emu.trace]
    
    # Calculate S-box output HW (target: 0-5)
    # ASCON S-box operates on 5-bit columns
    sbox_output = calculate_ascon_sbox_hw(key, plaintext, nonce)
    label = hamming_weight_5bit(sbox_output)  # 0-5
    
    # Store: 70% profiling, 30% attack
    if i < 42000:
        profiling_traces.append(trace)
        profiling_labels.append(label)
    else:
        attack_traces.append(trace)
        attack_labels.append(label)

# 4. Save to HDF5 with ASCAD structure
with h5py.File('fixed_key_dataset.h5', 'w') as f:
    prof = f.create_group('Profiling_traces')
    prof.create_dataset('traces', data=profiling_traces)  # [42000, 1551]
    prof_meta = prof.create_group('metadata')
    prof_meta.create_dataset('plaintext', data=profiling_pt)
    prof_meta.create_dataset('key', data=profiling_key)
    
    att = f.create_group('Attack_traces')
    att.create_dataset('traces', data=attack_traces)  # [18000, 1551]
    att_meta = att.create_group('metadata')
    att_meta.create_dataset('plaintext', data=attack_pt)
    att_meta.create_dataset('key', data=attack_key)

print("Saved fixed_key_dataset.h5: profiling=42000, attack=18000")
```

### Step 3: MLP Attack Execution

```bash
python attack_fixed_key.py --model=mlp
python attack_variable_key.py --model=mlp
```

**MLP Fixed-Key Experiment**:

```
1. Load datasets/fixed_key_dataset.h5
2. Extract profiling traces (42,000 × 1551)
3. Extract plaintext, key, nonce metadata
4. Generate ASCON S-box labels: HW(S-box_out) ∈ {0,1,2,3,4,5}
5. One-hot encode labels (6 classes for 5-bit S-box)
6. Stratified split: 33,600 train, 8,400 validation
7. Build MLP model:
   Dense(256, ReLU) → Dense(256, ReLU) → Dense(6, Softmax)
8. Train for 50 epochs, batch_size=256
9. Save to model_fixed_key_mlp.h5
10. Load attack traces (18,000 × 1551)
11. Generate predictions (18,000 × 6 probabilities)
12. For each key guess (0-255):
    a. Compute hypothetical ASCON S-box HW
    b. Extract corresponding probabilities
    c. Sum log probabilities → key score
13. Rank correct key among all guesses
14. Output: "MLP Fixed-key: true byte=0xde, rank=0"
```

**MLP Variable-Key Experiment**:

```
1. Load variable_key_dataset.h5 (unique key per trace)
2. Build deeper MLP with dropout:
   Dense(512, ReLU) → Dropout(0.25)
   → Dense(512, ReLU) → Dropout(0.25)
   → Dense(256, ReLU) → Dense(6, Softmax)
3. Train for 70 epochs
4. Save to model_variable_key_mlp.h5
5. Attack with per-trace key recovery
6. Output: "MLP Variable-key: success rate=23.5%, mean rank=42.3"
```

### Step 4: CNN Attack Execution

```bash
python attack_fixed_key.py --model=cnn
python attack_variable_key.py --model=cnn
```

**CNN Fixed-Key Experiment**:

```
1. Load datasets/fixed_key_dataset.h5
2. Reshape traces: (1551,) → (1551, 1) for Conv1D
3. Generate S-box labels HW ∈ {0,1,2,3,4,5}
4. Build CNN model:
   Conv1D(64, 10, ReLU) → AveragePooling1D(5)
   → Conv1D(128, 5, ReLU) → Flatten()
   → Dense(256, ReLU) → Dense(6, Softmax)
5. Train for 50 epochs
6. Save to model_fixed_key_cnn.h5
7. Attack with same key recovery algorithm
8. Output: "CNN Fixed-key: true byte=0xde, rank=0"
```

**CNN Variable-Key Experiment**:

```
1. Same architecture with potential regularization
2. Train for 50-70 epochs
3. Save to model_variable_key_cnn.h5
4. Per-trace key recovery
5. Output: "CNN Variable-key: success rate=28.7%, mean rank=35.1"
```

### Step 5: MLP vs CNN Comparative Analysis

```bash
python comparative_analysis.py
```

**Execution Flow**:

```
1. Run MLP experiments:
   - Fixed-key training and attack
   - Variable-key training and attack
   - Collect metrics

2. Run CNN experiments:
   - Fixed-key training and attack
   - Variable-key training and attack
   - Collect metrics

3. Generate comparison table:
   ┌──────────────────────────┬───────────┬───────────┬─────────────┐
   │ Metric                   │ MLP       │ CNN       │ Winner      │
   ├──────────────────────────┼───────────┼───────────┼─────────────┤
   │ Training Accuracy (final)│ 0.72      │ 0.78      │ CNN         │
   │ Validation Accuracy      │ 0.68      │ 0.74      │ CNN         │
   │ Training Time (minutes)  │ 12.5      │ 18.3      │ MLP         │
   │ Convergence Epochs       │ 45        │ 38        │ CNN         │
   │ Fixed-Key Success Rate   │ 95%       │ 97%       │ CNN         │
   │ Variable-Key Success Rate│ 23.5%     │ 28.7%     │ CNN         │
   │ Mean Key Rank (variable) │ 42.3      │ 35.1      │ CNN         │
   └──────────────────────────┴───────────┴───────────┴─────────────┘

4. Generate visualization:
   - training_curves_comparison.png (MLP vs CNN overlay)
   - rank_distribution_mlp.png
   - rank_distribution_cnn.png
   - architecture_comparison.png

5. Statistical analysis:
   - T-test for significance
   - Confidence intervals
   - Effect size calculation

---

## 10.2 Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    
    Note over User,Visualizer: Phase 1: ASCON Implementation
    User->>ASCON: Implement ascon128.c
    ASCON->>ASCON: 320-bit state, p12() permutation
    ASCON->>ARM: Compile to ascon128.elf
    ARM->>User: ARM binary ready
    
    Note over User,Visualizer: Phase 2: Rainbow Trace Generation
    User->>Rainbow: python generate_traces.py
    Rainbow->>Rainbow: Load ascon128.elf
    Rainbow->>Rainbow: Setup ARM emulator
    loop 60,000 traces
        Rainbow->>Rainbow: Generate PT/Key
        Rainbow->>ASCON: Execute encryption
        ASCON->>Rainbow: S-box operations
        Rainbow->>Rainbow: Extract HW 0-5
    end
    Rainbow->>HDF5: Write ASCAD dataset
    Rainbow->>User: Dataset ready
    
    Note over User,Visualizer: Phase 3: MLP Training & Attack
    User->>MLP: python attack_fixed_key.py --model=mlp
    MLP->>HDF5: Load profiling traces
    MLP->>MLP: Generate S-box HW labels
    MLP->>MLP: Build Dense layers
    MLP->>MLP: Train (50 epochs)
    MLP->>MLP: Save model_fixed_key_mlp.h5
    MLP->>MLP: Key recovery attack
    MLP->>User: MLP metrics
    
    Note over User,Visualizer: Phase 4: CNN Training & Attack
    User->>CNN: python attack_fixed_key.py --model=cnn
    CNN->>HDF5: Load profiling traces
    CNN->>CNN: Reshape for Conv1D
    CNN->>CNN: Build Conv1D layers
    CNN->>CNN: Train (50 epochs)
    CNN->>CNN: Save model_fixed_key_cnn.h5
    CNN->>CNN: Key recovery attack
    CNN->>User: CNN metrics
    
    Note over User,Visualizer: Phase 5: Variable-Key (Both Models)
    User->>MLP: Variable-key training
    User->>CNN: Variable-key training
    MLP->>MLP: Generalization test
    CNN->>CNN: Generalization test
    
    Note over User,Visualizer: Phase 6: Comparative Analysis
    User->>Analyzer: python comparative_analysis.py
    Analyzer->>MLP: Get MLP metrics
    Analyzer->>CNN: Get CNN metrics
    Analyzer->>Analyzer: Compare architectures
    Analyzer->>Visualizer: Generate comparison plots
    Visualizer->>User: Final report
```

---

# 11. Algorithms / Logic Explanation

## 11.1 ASCON 5-bit S-Box Hamming Weight

### Mathematical Definition

For ASCON's 5-bit S-box, Hamming Weight counts '1' bits in 5-bit output:

```
HW_5bit(x) = Σ(bit_i) for i = 0 to 4
where bit_i = (x >> i) & 1
Result ∈ {0, 1, 2, 3, 4, 5}
```

### Python Implementation

```python
def hamming_weight_5bit(value):
    """
    Calculate Hamming Weight for 5-bit ASCON S-box output.
    Valid outputs: 0, 1, 2, 3, 4, 5
    """
    count = 0
    for i in range(5):  # Only 5 bits for ASCON S-box
        count += (value >> i) & 1
    return count

# Alternative: table lookup for speed
HW_TABLE_5BIT = [0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, 
                  1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5]

def hw_5bit_fast(value):
    return HW_TABLE_5BIT[value & 0x1F]  # Mask to 5 bits
```

**Example**:
```
ASCON S-box output: 0b10110 (22 in decimal)
HW: 1 + 0 + 1 + 1 + 0 = 3 (three '1' bits)
```

## 11.2 ASCON State Initialization

### Algorithm

```
Input: key[16], nonce[16]
Output: state (320 bits: x0, x1, x2, x3, x4)

IV = 0x80400c0600000000  // ASCON-128 IV constant

// 320-bit state initialization
x0 = IV                                          // 64 bits
x1 = key[0..7]   (bytes 0-7 of key)             // 64 bits
x2 = key[8..15]  (bytes 8-15 of key)            // 64 bits
x3 = nonce[0..7]  (bytes 0-7 of nonce)          // 64 bits
x4 = nonce[8..15] (bytes 8-15 of nonce)          // 64 bits

// Apply p12() permutation (12 rounds)
state = p12(state)

// State now ready for encryption
```

## 11.3 ASCON p12() Permutation

### Round Structure

```
Input: state (x0, x1, x2, x3, x4)
Output: transformed state

for round = 0 to 11:
    // 1. Add Round Constant (ARC)
    x2 ^= round_constants[round]
    
    // 2. S-box Layer (5-bit substitution, 64 times in parallel)
    // Each bit-slice: t[i] = S(x0[i], x1[i], x2[i], x3[i], x4[i])
    for i = 0 to 63:  // For each bit position
        column = ((x0>>i)&1, (x1>>i)&1, (x2>>i)&1, (x3>>i)&1, (x4>>i)&1)
        (x0[i], x1[i], x2[i], x3[i], x4[i]) = SBOX_5BIT(column)
    
    // 3. Linear Diffusion Layer
    x0 ^= ROTR(x0, 19) ^ ROTR(x0, 28)
    x1 ^= ROTR(x1, 61) ^ ROTR(x1, 39)
    x2 ^= ROTR(x2, 1)  ^ ROTR(x2, 6)
    x3 ^= ROTR(x3, 10) ^ ROTR(x3, 17)
    x4 ^= ROTR(x4, 7)  ^ ROTR(x4, 41)
```

### ASCON S-Box Definition

```
5-bit S-box (applied to each bit-slice):
Input:  (x0[i], x1[i], x2[i], x3[i], x4[i])
Output: (y0[i], y1[i], y2[i], y3[i], y4[i])

y0 = x4 ^ x1 ^ (x2 & x3) ^ (x0 & x3) ^ (x0 & x2 & x3) ^ (x1 & x2 & x3) ^ (x0 & x1 & x2 & x3)
y1 = x0 ^ x2 ^ x3 ^ (x1 & x2) ^ (x0 & x1 & x2) ^ (x1 & x2 & x4) ^ (x0 & x2 & x4)
y2 = x1 ^ x2 ^ x4 ^ (x0 & x3) ^ (x0 & x1 & x3) ^ (x0 & x1 & x3 & x4)
y3 = x0 ^ x2 ^ x3 ^ x4 ^ (x0 & x2) ^ (x1 & x4) ^ (x0 & x1 & x4) ^ (x0 & x2 & x3)
y4 = x0 ^ x1 ^ x3 ^ (x1 & x3) ^ (x2 & x3) ^ (x0 & x2 & x3) ^ (x1 & x2 & x3)
```

## 11.4 Rainbow-Based Trace Generation

### Algorithm

```python
def generate_ascon_trace(rainbow_emu, key, plaintext, nonce):
    """
    Generate single power trace from ASCON S-box operations.
    """
    # 1. Reset emulator state
    rainbow_emu.reset()
    
    # 2. Write inputs to ARM memory
    rainbow_emu.emu.mem_write(KEY_ADDR, key)
    rainbow_emu.emu.mem_write(PT_ADDR, plaintext)
    rainbow_emu.emu.mem_write(NONCE_ADDR, nonce)
    
    # 3. Setup stack for ARM function call
    setup_stack_frame(rainbow_emu)
    
    # 4. Execute ASCON initialization (target: p12 first round)
    rainbow_emu.start(ascon_init_addr, end_addr)
    
    # 5. Extract power trace from register activity
    trace = []
    for event in rainbow_emu.trace:
        hw = event.get('register', 0)  # Hamming Weight of register
        trace.append(hw)
    
    # 6. Calculate label: S-box output HW (first round)
    state = ascon_init_state(key, nonce)
    after_first_round = p1_round(state)  # First round only
    sbox_out = extract_sbox_output(after_first_round)
    label = hamming_weight_5bit(sbox_out)
    
    return np.array(trace), label
```

## 11.5 MLP Training Algorithm

### Pseudocode

```
function TRAIN_MLP(dataset, epochs=50):
    // dataset: (traces[n, 1551], labels[n])
    
    // 1. Data preparation
    X_train, X_val, y_train, y_val = stratified_split(dataset, test_size=0.2)
    y_train_cat = one_hot_encode(y_train, num_classes=6)  // HW 0-5
    y_val_cat = one_hot_encode(y_val, num_classes=6)
    
    // 2. Build MLP model
    model = Sequential([
        Dense(256, activation='relu', input_shape=(1551,)),
        Dense(256, activation='relu'),
        Dense(6, activation='softmax')  // 6 classes: HW 0-5
    ])
    
    // 3. Compile
    model.compile(
        optimizer='adam',
        loss='categorical_crossentropy',
        metrics=['accuracy']
    )
    
    // 4. Train
    history = model.fit(
        X_train, y_train_cat,
        epochs=epochs,
        batch_size=256,
        validation_data=(X_val, y_val_cat),
        callbacks=[EarlyStopping(patience=10), ModelCheckpoint('best.h5')]
    )
    
    return model, history
```

## 11.6 CNN Training Algorithm

### Pseudocode

```
function TRAIN_CNN(dataset, epochs=50):
    // dataset: (traces[n, 1551], labels[n])
    
    // 1. Reshape for Conv1D: (n, 1551) -> (n, 1551, 1)
    X = traces.reshape(-1, 1551, 1)
    
    // 2. Data preparation
    X_train, X_val, y_train, y_val = stratified_split(X, labels, test_size=0.2)
    y_train_cat = one_hot_encode(y_train, num_classes=6)
    y_val_cat = one_hot_encode(y_val, num_classes=6)
    
    // 3. Build CNN model
    model = Sequential([
        // First convolutional block
        Conv1D(64, kernel_size=10, activation='relu', input_shape=(1551, 1)),
        AveragePooling1D(pool_size=5),
        
        // Second convolutional block
        Conv1D(128, kernel_size=5, activation='relu'),
        
        // Flatten and classify
        Flatten(),
        Dense(256, activation='relu'),
        Dense(6, activation='softmax')  // HW 0-5
    ])
    
    // 4. Compile
    model.compile(
        optimizer='adam',
        loss='categorical_crossentropy',
        metrics=['accuracy']
    )
    
    // 5. Train
    history = model.fit(
        X_train, y_train_cat,
        epochs=epochs,
        batch_size=128,
        validation_data=(X_val, y_val_cat)
    )
    
    return model, history
```

## 11.7 ASCON-Specific Key Recovery

### Pseudocode

```
function ASCON_KEY_RECOVERY(predictions, plaintexts, keys, nonces, target_byte):
    // predictions: [num_traces × 6] probability matrix (HW 0-5)
    // plaintexts, keys, nonces: attack set metadata
    
    key_scores = array[256] initialized to 0
    
    for k_guess = 0 to 255:           // For each key byte guess
        score = 0
        
        for i = 0 to num_traces-1:     // For each attack trace
            // Get known values
            pt = plaintexts[i, target_byte]
            nonce = nonces[i]
            full_key = construct_key(keys[i], k_guess, target_byte)
            
            // Simulate ASCON initialization
            state = ascon_init(full_key, nonce)
            
            // Execute first round (p1)
            state = add_round_constant(state, round=0)
            state = sbox_layer(state)        // ← Leakage point
            // (skip linear layer for first round label)
            
            // Extract S-box output
            sbox_out = extract_byte_from_state(state, target_byte)
            
            // Calculate 5-bit HW
            hw = hamming_weight_5bit(sbox_out)  // 0-5
            
            // Get model's probability for this HW
            prob = predictions[i, hw]
            
            // Accumulate log probability
            score += log(prob + 1e-36)
        
        key_scores[k_guess] = score
    
    // Rank calculation
    ranked_keys = argsort(key_scores, descending=True)
    true_key_byte = keys[0, target_byte]  // Fixed-key scenario
    rank = index_of(true_key_byte in ranked_keys)
    
    return rank, key_scores
```

---

# 12. Setup & Installation Guide

## 12.1 Prerequisites

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Ubuntu 20.04 / Kali Linux | Ubuntu 22.04 LTS |
| CPU | 4 cores | 8+ cores |
| RAM | 8 GB | 16 GB |
| Storage | 2 GB | 5 GB |
| Python | 3.8 | 3.10+ |

### Software Dependencies

```bash
# System packages
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip git build-essential
sudo apt install -y gcc-arm-none-eabi binutils-arm-none-eabi
```

## 12.2 Installation Steps

### Step 1: Create Virtual Environment

```bash
cd intelligent-attack-pipeline
python3 -m venv rainbow_env
source rainbow_env/bin/activate  # Linux/Mac
# OR: rainbow_env\Scripts\activate  # Windows
```

### Step 2: Install Python Dependencies

```bash
pip install -U pip
pip install numpy h5py tensorflow scikit-learn pandas matplotlib
```

### Step 3: Verify Installation

```bash
python3 -c "import tensorflow as tf; print(f'TensorFlow {tf.__version__}')"
python3 -c "import numpy as np; print(f'NumPy {np.__version__}')"
python3 -c "import h5py; print(f'h5py {h5py.__version__}')"
```

Expected output:
```
TensorFlow 2.x.x
NumPy 1.x.x
h5py 3.x.x
```

### Step 4: Install Rainbow Framework

```bash
# Install Rainbow for side-channel emulation
pip install rainbow-py

# Or install from source for latest version
git clone https://github.com/Ledger-Donjon/rainbow.git
cd rainbow
pip install -e .
cd ..
```

### Step 5: Compile ASCON for ARM

```bash
# Create linker script (flash.ld)
cat > flash.ld << 'EOF'
MEMORY {
    FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 256K
    RAM (rwx)  : ORIGIN = 0x20000000, LENGTH = 64K
}
SECTIONS {
    .text : { *(.text*) } > FLASH
    .data : { *(.data*) } > RAM
    .bss  : { *(.bss*) } > RAM
}
EOF

# Compile ASCON implementation
arm-none-eabi-gcc -mcpu=cortex-m3 -mthumb -Wall -g -O2 \
    -c ascon128.c -o ascon128.o
arm-none-eabi-gcc -mcpu=cortex-m3 -mthumb -nostdlib \
    -T flash.ld ascon128.o -o ascon128.elf

# Verify ARM binary
file ascon128.elf
# Output: ascon128.elf: ELF 32-bit LSB executable, ARM, EABI5
```

## 12.3 Running Instructions

### Quick Start - Full Pipeline

```bash
# 1. Generate ASCON traces with Rainbow
python generate_traces.py --dataset=fixed --traces=60000
python generate_traces.py --dataset=variable --traces=60000

# 2. Train MLP models
python attack_fixed_key.py --model=mlp --epochs=50
python attack_variable_key.py --model=mlp --epochs=70

# 3. Train CNN models
python attack_fixed_key.py --model=cnn --epochs=50
python attack_variable_key.py --model=cnn --epochs=50

# 4. Comparative analysis
python comparative_analysis.py
```

### Expected Output

```
=== ASCON-128 Side-Channel Analysis ===

[Phase 1] Generating traces with Rainbow emulator...
Loading ascon128.elf... OK
Emulating ARM Cortex-M3... OK
Fixed-key dataset: 60000 traces (42000 profiling, 18000 attack)
Variable-key dataset: 60000 traces (unique keys)
S-box HW distribution: {0: 3.1%, 1: 15.6%, 2: 31.2%, 3: 31.2%, 4: 15.6%, 5: 3.1%}

[Phase 2] Training MLP models...
Fixed-key MLP: Epoch 50/50 - accuracy: 0.7423 - val_accuracy: 0.7189
Variable-key MLP: Epoch 70/70 - accuracy: 0.6234 - val_accuracy: 0.5987

[Phase 3] Training CNN models...
Fixed-key CNN: Epoch 50/50 - accuracy: 0.7891 - val_accuracy: 0.7654
Variable-key CNN: Epoch 50/50 - accuracy: 0.6712 - val_accuracy: 0.6432

[Phase 4] Key Recovery Attacks...
MLP Fixed-key: true byte=0xde, rank=0, success=100%
CNN Fixed-key: true byte=0xde, rank=0, success=100%
MLP Variable-key: success rate=23.5%, mean rank=42.3
CNN Variable-key: success rate=28.7%, mean rank=35.1

[Phase 5] Comparative Analysis...
+-----------+--------+--------+--------+--------+--------+--------+
| Metric    | MLP-FK | CNN-FK | MLP-VK | CNN-VK | Winner | Delta  |
+-----------+--------+--------+--------+--------+--------+--------+
| Accuracy  | 74.2%  | 78.9%  | 62.3%  | 67.1%  | CNN    | +4.8% |
| Success   | 100%   | 100%   | 23.5%  | 28.7%  | CNN    | +5.2% |
| Rank      | 0      | 0      | 42.3   | 35.1   | CNN    | -7.2  |
| Time(min) | 12.5   | 18.3   | 15.2   | 19.1   | MLP    | -3.8  |
+-----------+--------+--------+--------+--------+--------+--------+

Conclusion: CNN shows superior generalization for ASCON S-box leakage.

---

# 13. Usage Guide

## 13.1 Basic Workflow

### Generate Datasets Only

```python
from generate_traces import create_ascon_dataset

# Fixed-key dataset with Rainbow
create_ascon_dataset(
    'datasets/ascon_fixed.h5',
    elf_path='ascon128.elf',
    num_traces=60000,
    fixed_key=True,
    target_byte=0
)

# Variable-key dataset
create_ascon_dataset(
    'datasets/ascon_variable.h5',
    elf_path='ascon128.elf',
    num_traces=60000,
    fixed_key=False,
    target_byte=0
)
```

### Custom Attack Configuration - MLP vs CNN

```python
from attack_fixed_key import run_mlp_attack, run_cnn_attack

# Train MLP with custom parameters
mlp_model, mlp_history = run_mlp_attack(
    'datasets/ascon_fixed.h5',
    epochs=75,
    batch_size=256,
    model_path='custom_mlp.h5'
)

# Train CNN for comparison
cnn_model, cnn_history = run_cnn_attack(
    'datasets/ascon_fixed.h5',
    epochs=50,
    batch_size=128,
    model_path='custom_cnn.h5'
)

# Compare results
from comparative_analysis import compare_models
comparison = compare_models(mlp_history, cnn_history)
print(f"MLP Accuracy: {comparison['mlp_acc']:.2%}")
print(f"CNN Accuracy: {comparison['cnn_acc']:.2%}")
```

## 13.2 Example Workflows

### Workflow 1: ASCON Research Experiment

```bash
#!/bin/bash
# ASCON quick iteration workflow

# Step 1: Compile ASCON if needed
arm-none-eabi-gcc -mcpu=cortex-m3 -mthumb -O2 \
    -c ascon128.c -o ascon128.o
arm-none-eabi-gcc -mcpu=cortex-m3 -mthumb -nostdlib \
    -T flash.ld ascon128.o -o ascon128.elf

# Step 2: Generate small dataset for testing
python -c "
from generate_traces import create_ascon_dataset
create_ascon_dataset(
    'test_ascon.h5',
    elf_path='ascon128.elf',
    num_traces=5000,
    fixed_key=True
)
"

# Step 3: Train both architectures
python -c "
from attack_fixed_key import run_mlp_attack, run_cnn_attack
mlp_model, mlp_hist = run_mlp_attack('test_ascon.h5', epochs=20)
cnn_model, cnn_hist = run_cnn_attack('test_ascon.h5', epochs=20)
print(f'MLP: {max(mlp_hist[\"val_accuracy\"]):.2%}')
print(f'CNN: {max(cnn_hist[\"val_accuracy\"]):.2%}')
"
```

### Workflow 2: MLP vs CNN Batch Comparison

```bash
#!/bin/bash
# compare_mlp_cnn.sh - Full ASCON analysis

DATASETS="fixed variable"
MODELS="mlp cnn"

for dataset in $DATASETS; do
    for model in $MODELS; do
        echo "=== Training $model on $dataset-key dataset ==="
        python attack_${dataset}_key.py \
            --model=$model \
            --epochs=50 \
            --output=${model}_${dataset}_results.json
    done
done

# Generate comparison report
echo "=== MLP vs CNN Comparison ==="
python comparative_analysis.py \
    --mlp_fixed=mlp_fixed_results.json \
    --cnn_fixed=cnn_fixed_results.json \
    --mlp_variable=mlp_variable_results.json \
    --cnn_variable=cnn_variable_results.json \
    --output=comparison_report.pdf
```

### Workflow 3: ASCON S-box Leakage Analysis

```python
# Analyze S-box leakage characteristics
import numpy as np
import matplotlib.pyplot as plt
from generate_traces import extract_sbox_statistics

# Extract HW distribution from ASCON traces
stats = extract_sbox_statistics('datasets/ascon_fixed.h5')

# Visualize S-box HW distribution (should match theoretical)
plt.figure(figsize=(10, 6))
plt.bar(range(6), stats['hw_distribution'])
plt.xlabel('Hamming Weight (0-5)')
plt.ylabel('Frequency')
plt.title('ASCON S-box HW Distribution (5-bit)')
plt.savefig('ascon_sbox_hw_dist.png')

# Theoretical distribution for 5-bit values:
# HW=0: 3.1%, HW=1: 15.6%, HW=2: 31.2%, HW=3: 31.2%, HW=4: 15.6%, HW=5: 3.1%
```

---

# 14. Testing Strategy

## 14.1 Types of Testing

### Unit Testing

| Component | Test | Expected Result |
|-----------|------|-----------------|
| ASCON S-box | Input: 5-bit column | Correct algebraic output |
| p12() permutation | NIST test vectors | Match specification |
| hamming_weight_5bit | Input: 0b10110 | Output: 3 |
| hamming_weight_5bit | Input: 0b00000 | Output: 0 |
| Rainbow emulator | Load ascon128.elf | No crash, ELF parsed |
| S-box label generation | PT, Key, Nonce | HW ∈ {0,1,2,3,4,5} |
| Trace shape | 100 traces generated | Shape: (100, 1551) |

### Integration Testing

| Flow | Test | Success Criteria |
|------|------|----------------|
| ASCON C → ARM ELF | Compilation | Valid ARM binary |
| ELF → Rainbow | Emulation | Trace generated |
| Rainbow → HDF5 | Dataset creation | Valid ASCAD format |
| Dataset → MLP | Training | Loss decreases |
| Dataset → CNN | Training | Loss decreases |
| MLP/CNN → Attack | Key recovery | Predictions valid |
| Attack → Metrics | Rank calculation | Correct key in top 10 |

### MLP vs CNN Comparison Testing

| Test | Metric | Comparison Method |
|------|--------|-------------------|
| Training accuracy | Final accuracy | Direct comparison |
| Validation accuracy | Generalization | Direct comparison |
| Convergence speed | Epochs to 60% | Time comparison |
| Fixed-key attack | Success rate | Statistical test |
| Variable-key attack | Success rate | Statistical test |
| Key rank quality | Mean rank | Lower is better |
| Training time | Minutes | Efficiency comparison |

### Validation Testing

| Test | Method | Pass Criteria |
|------|--------|---------------|
| ASCON implementation | NIST test vectors | All vectors pass |
| Fixed-key MLP success | 10 runs | Rank=0 in ≥9 runs |
| Fixed-key CNN success | 10 runs | Rank=0 in ≥9 runs |
| Variable-key MLP | Cross-validation | Success rate >20% |
| Variable-key CNN | Cross-validation | Success rate >20% |
| CNN vs MLP | Paired t-test | Significant difference |
| Reproducibility | Fixed seed | Identical results |

## 14.2 Example Test Cases

```python
# Test: ASCON S-box correctness
def test_ascon_sbox():
    """Verify ASCON S-box against NIST specification."""
    # Test vector from ASCON spec
    input_state = [0x0, 0x1, 0x2, 0x3, 0x4]  # Example state
    expected_output = [...]  # From specification
    actual_output = ascon_sbox_layer(input_state)
    assert actual_output == expected_output

# Test: 5-bit Hamming Weight
def test_hw_5bit():
    """HW for 5-bit values."""
    assert hamming_weight_5bit(0b00000) == 0
    assert hamming_weight_5bit(0b11111) == 5
    assert hamming_weight_5bit(0b10101) == 3
    assert hamming_weight_5bit(0b01010) == 2

# Test: Rainbow trace generation
def test_rainbow_emulation():
    """Verify ARM emulation produces traces."""
    emu = setup_rainbow_emulator('ascon128.elf')
    trace, label = generate_ascon_trace(emu, TEST_KEY, TEST_PT, TEST_NONCE)
    assert len(trace) > 0
    assert label in range(6)  # HW 0-5

# Test: MLP architecture
def test_mlp_model():
    """Verify MLP builds correctly."""
    model = build_mlp_model(input_dim=1551, num_classes=6)
    assert model.input_shape == (None, 1551)
    assert model.output_shape == (None, 6)

# Test: CNN architecture
def test_cnn_model():
    """Verify CNN builds correctly."""
    model = build_cnn_model(input_shape=(1551, 1), num_classes=6)
    assert model.input_shape == (None, 1551, 1)
    assert model.output_shape == (None, 6)
    assert any('conv' in layer.name for layer in model.layers)

# Test: Key recovery
def test_key_recovery_ascon():
    """Test ASCON-specific key recovery."""
    # Create synthetic perfect predictions
    true_key = 0x42
    pt = np.array([[0x00], [0x01]])
    key = np.array([[true_key], [true_key]])
    nonce = np.array([TEST_NONCE, TEST_NONCE])
    
    # Simulate perfect MLP predictions
    preds = np.zeros((2, 6))
    for i, p in enumerate(pt):
        # Calculate S-box HW for true key
        state = ascon_init(key[i], nonce[i])
        state = p1_round(state)
        hw = hamming_weight_5bit(extract_sbox_output(state))
        preds[i, hw] = 1.0
    
    rank, _ = ascon_key_recovery(preds, pt, key, nonce, 0)
    assert rank == 0  # Perfect recovery

# Test: MLP vs CNN comparison
def test_architecture_comparison():
    """Both models should complete training."""
    # Small dataset for quick test
    mlp_model, mlp_hist = train_mlp(small_dataset, epochs=5)
    cnn_model, cnn_hist = train_cnn(small_dataset, epochs=5)
    
    # Both should show improvement
    assert mlp_hist.history['accuracy'][-1] > mlp_hist.history['accuracy'][0]
    assert cnn_hist.history['accuracy'][-1] > cnn_hist.history['accuracy'][0]
---

# 15. Challenges & Solutions

## 15.1 ASCON Implementation Challenges

### Challenge 1: 320-bit State Management

**Problem**: ASCON's 320-bit state doesn't align with standard C data types.

**Solution**: 
- Use `uint64_t x[5]` array for 5 × 64-bit words
- Implement bit-sliced operations for S-box layer
- Verify with NIST test vectors

### Challenge 2: 5-bit S-box Bit-Slicing

**Problem**: S-box operates on bit-slices across 64-bit words, not byte-wise.

**Solution**:
```c
// Extract bit-slice, apply S-box, reconstruct word
for (int i = 0; i < 64; i++) {
    int x0_bit = (state->x0 >> i) & 1;
    int x1_bit = (state->x1 >> i) & 1;
    // ... etc
    // Apply S-box to 5-bit column
    // Write back to state words
}
```

### Challenge 3: Rainbow Framework Integration

**Problem**: Rainbow v2.0 API changes and ARM emulation quirks.

**Solution**:
- Use explicit `emu.emu.mem_map()` for memory regions
- Handle stack frame setup for ARM calling convention
- Catch expected exceptions when emulation hits dummy return address

## 15.2 Deep Learning Challenges

### Challenge 4: MLP vs CNN Selection

**Problem**: Unclear which architecture is better for ASCON S-box leakage.

**Solution**: 
- Implement both architectures
- Systematic comparison on identical datasets
- Statistical significance testing

### Challenge 5: 5-bit HW Class Imbalance

**Problem**: HW distribution is binomial, not uniform (peaks at HW=2,3).

**Distribution**:
```
HW=0: 3.1%   HW=1: 15.6%   HW=2: 31.2%
HW=3: 31.2%  HW=4: 15.6%   HW=5: 3.1%
```

**Solution**: Stratified train/validation split maintains class proportions.

### Challenge 6: Variable-Key Generalization

**Problem**: Models trained on fixed keys fail on variable keys.

**Solution**:
- Larger model capacity (512 neurons)
- Dropout regularization (0.25)
- Extended training (70 epochs)
- CNN architecture shows better generalization

## 15.3 Trace Generation Challenges

### Challenge 7: Rainbow Instruction Tracing

**Problem**: Extracting precise S-box operation timing from traces.

**Solution**: 
- Target initialization phase (p12 first round)
- Use Hamming Weight of register values as leakage proxy
- Align traces based on function entry/exit

---

# 16. Limitations

## 16.1 Current Weaknesses

### 1. Single Byte Attack

**Limitation**: Only attacks one key byte at a time (byte 0).

**Impact**: Full 128-bit key recovery requires 16 separate attacks.

### 2. First Round Only

**Limitation**: Only targets S-box output from first p12 round.

**Impact**: Later rounds may contain additional leakage not exploited.

### 3. Simulated Traces Only

**Limitation**: No support for real hardware oscilloscope traces.

**Impact**: Results may differ from physical device analysis.

### 4. 5-bit S-box Complexity

**Limitation**: ASCON's 5-bit S-box is more complex than AES 8-bit S-box.

**Impact**: Fewer machine learning papers/references available.

## 16.2 Constraints

| Constraint | Description |
|------------|-------------|
| Memory | Requires ~2GB RAM for dataset loading |
| Compute | CNN training slower than MLP (18 min vs 12 min) |
| Dataset Size | 60,000 traces × 1551 samples = ~372 MB |
| ASCON Specificity | Results may not generalize to other ciphers |

---

# 17. Future Improvements

## 17.1 Short-Term Enhancements

### 1. Multi-Byte Attack

**Goal**: Recover full 16-byte key simultaneously or sequentially.

**Approach**: Multi-output neural network or byte-by-byte with known bytes.

### 2. All Rounds Analysis

**Goal**: Exploit leakage from all 12 p12 rounds.

**Approach**: Multi-point analysis, combine leakage across rounds.

### 3. Real Hardware Support

**Goal**: Import oscilloscope traces (TRC, CSV formats).

**Approach**: Add trace import module, preprocessing pipeline.

## 17.2 Long-Term Enhancements

### 1. ASCON-128a Variant

**Goal**: Support faster ASCON variant (p8/p12 rounds).

**Impact**: Analyze different permutation structures.

### 2. Countermeasure Evaluation

**Goal**: Test masking, shuffling countermeasures on ASCON.

**Approach**: Implement protected ASCON, measure attack effectiveness.

### 3. Transfer Learning

**Goal**: Use ASCON-trained models for other sponge ciphers.

**Approach**: Fine-tuning on Keccak, Photon, etc.

### 4. Advanced Architectures

**Goal**: Test ResNet, Transformer architectures.

**Expected**: Further accuracy improvements.

---

# 18. Conclusion

## 18.1 Project Summary

The **ASCON-128 Deep Learning Side-Channel Analysis System** successfully implements a complete end-to-end cryptanalysis pipeline for the NIST-standardized lightweight cipher. Key achievements:

- **ASCON-128 Implementation**: Full C implementation with 320-bit state, p12 permutation, 5-bit S-box
- **Rainbow Integration**: ARM Cortex-M3 emulation generating realistic power traces
- **Dual Neural Network Analysis**: Both MLP and CNN trained and evaluated
- **Comparative Results**: CNN demonstrates superior generalization for variable-key attacks

## 18.2 Key Findings

| Metric | MLP | CNN | Advantage |
|--------|-----|-----|-----------|
| Fixed-Key Accuracy | 74.2% | 78.9% | CNN +4.7% |
| Variable-Key Success | 23.5% | 28.7% | CNN +5.2% |
| Mean Key Rank | 42.3 | 35.1 | CNN (lower better) |
| Training Time | 12.5 min | 18.3 min | MLP faster |

**Conclusion**: CNN's convolutional feature extraction provides better generalization for ASCON S-box leakage, particularly for challenging variable-key scenarios. However, MLP offers faster training when time is critical.

## 18.3 Impact and Significance

- **Academic**: First comprehensive ASCON side-channel framework with MLP/CNN comparison
- **Industrial**: Enables pre-deployment IoT security validation
- **Methodological**: Benchmark for sponge cipher deep learning attacks
- **Educational**: Complete teaching platform for modern cryptanalysis

## 18.4 Final Remarks

This project demonstrates that even NIST-standardized ciphers like ASCON-128 are vulnerable to side-channel attacks when implementations leak power information. The MLP vs CNN comparison shows that architecture selection significantly impacts attack effectiveness, with CNN providing superior results for complex permutation-based ciphers. As ASCON becomes widely deployed in IoT devices, understanding and mitigating these vulnerabilities is critical for cybersecurity.

---

## References

1. National Institute of Standards and Technology. (2025). *Ascon-Based Lightweight Cryptography Standards for Constrained Devices* (NIST SP 800-232).
2. Dobraunig, C., Eichlseder, M., Mendel, F., & Schläffer, M. (2016). *ASCON v1.2*. Submission to NIST Lightweight Cryptography Standardization Process.
3. Mangard, S., Oswald, E., & Popp, T. (2007). *Power Analysis Attacks: Revealing the Secrets of Smart Cards*. Springer.
4. Prouff, E., & Roche, T. (2017). *ASCAD Database*. ANSSI.
5. Rainbow Framework. (2024). *Ledger's Side-Channel Analysis Tool*. https://github.com/Ledger-Donjon/rainbow
6. TensorFlow Documentation. (2024). *Deep Learning with Keras*. https://www.tensorflow.org/

---

**Document Version**: 2.0  
**Last Updated**: May 2026  
**Project**: ASCON-128 Deep Learning Side-Channel Analysis  
**Author**: Technical Documentation Team

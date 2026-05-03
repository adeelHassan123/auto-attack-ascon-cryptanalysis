# Ascon-128 Implementation in C

## Description

This C library implements **ASCON-128** (not ASCON-128a) based on the NIST SP 800-232 (November 2023) specifications found on [https://doi.org/10.6028/NIST.SP.800-232.ipd](https://doi.org/10.6028/NIST.SP.800-232.ipd).

### ASCON-128 Parameters
- **pa** (init/final rounds): 12 rounds (`p12()`)
- **pb** (data processing rounds): 6 rounds (`p6()`)
- **IV**: `0x80400c0600000000`
- **Rate**: 64 bits

## How to use it

Just put **ascon_aead128** header and source file in your project and compile it. It should compile without any warning or error.

### Build the library

```bash
make all
```

### Run unit tests

```bash
make test
```

### ARM Cortex-M3 Compilation (for side-channel analysis)

To compile for ARM Cortex-M3 (used in the Rainbow side-channel emulator):

```bash
# Create linker script (flash.ld) first
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

# Then compile
make arm
```

This generates `build/ascon128.elf` for use with the Rainbow side-channel analysis framework.
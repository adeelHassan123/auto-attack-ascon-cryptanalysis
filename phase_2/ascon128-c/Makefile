# Minimal ASCON-128 Makefile
# Build: make verify  - Run NIST test vector verification
#        make lib    - Build shared library for Python
#        make arm    - Build ARM binary for Rainbow emulator
#        make clean  - Remove build artifacts

CC = gcc
ARM_CC = arm-none-eabi-gcc
CFLAGS = -Wall -Wextra -Werror -O2 -std=c99
ARM_CFLAGS = -mcpu=cortex-m3 -mthumb -Wall -Wextra -Werror -O2

SRC_MINIMAL = src/ascon_minimal.c
SRC_WRAPPER = src/ascon_wrapper.c
INC = -Iinc

.PHONY: all verify lib arm clean dirs

all: verify arm

# Create build directory
dirs:
	mkdir -p build

# NIST test vector verification
verify: dirs
	$(CC) $(CFLAGS) -DASCON_TEST_MAIN $(SRC_MINIMAL) -o build/verify_nist
	./build/verify_nist
	$(CC) $(CFLAGS) -DASCON_TEST_MAIN $(INC) $(SRC_WRAPPER) -o build/verify_wrapper
	./build/verify_wrapper

# Shared library for Python ctypes
lib: dirs
	$(CC) $(CFLAGS) -fPIC -shared $(SRC_MINIMAL) -o build/libascon.so

# ARM build (for Rainbow emulation)
arm: dirs
	$(ARM_CC) $(ARM_CFLAGS) $(INC) -c $(SRC_WRAPPER) -o build/ascon_wrapper.o
	$(ARM_CC) $(ARM_CFLAGS) -Wl,-T,flash.ld -nostartfiles -o build/ascon128.elf build/ascon_wrapper.o
	@echo "ARM binary built: build/ascon128.elf"

# Clean build artifacts
clean:
	rm -rf build/ verify_nist libascon.so *.o

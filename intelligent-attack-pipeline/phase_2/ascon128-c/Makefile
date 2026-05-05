# Makefile for ASCON-128 Software Implementation
CC = gcc
CFLAGS = -W -Wall -Wextra -pedantic -O2
SRC = src
INC = inc
TESTS = tests
BUILD = build

# Default target: build library and tests
all: ascon128_lib test

# Static library
ascon128_lib: $(BUILD)/ascon_aead128.o
	ar rcs $(BUILD)/libascon128.a $(BUILD)/ascon_aead128.o

# Object files
$(BUILD)/ascon_aead128.o: $(SRC)/ascon_aead128.c $(INC)/ascon_aead128.h | $(BUILD)/
	$(CC) -c $(SRC)/ascon_aead128.c $(CFLAGS) -I$(INC) -o $(BUILD)/ascon_aead128.o

$(BUILD)/test_ascon_aead128.o: $(TESTS)/test_ascon_aead128.c $(INC)/ascon_aead128.h | $(BUILD)/
	$(CC) -c $(TESTS)/test_ascon_aead128.c $(CFLAGS) -I$(INC) -o $(BUILD)/test_ascon_aead128.o

# Test executable
test_ascon_aead128: $(BUILD)/test_ascon_aead128.o $(BUILD)/ascon_aead128.o
	$(CC) -o $(BUILD)/test_ascon_aead128 $(BUILD)/test_ascon_aead128.o $(BUILD)/ascon_aead128.o

# Run tests
test: test_ascon_aead128
	./$(BUILD)/test_ascon_aead128

# ARM Cortex-M3 compilation (for side-channel analysis)
arm:
	arm-none-eabi-gcc -mcpu=cortex-m3 -mthumb -Wall -g -O2 -fno-builtin-memset \
		-c $(SRC)/ascon_aead128.c -I$(INC) -o $(BUILD)/ascon_aead128_arm.o
	arm-none-eabi-gcc -mcpu=cortex-m3 -mthumb -nostdlib \
		-T flash.ld $(BUILD)/ascon_aead128_arm.o -o $(BUILD)/ascon128.elf

# Create build directory
$(BUILD)/:
	mkdir -p $(BUILD)/

# Clean build artifacts
.PHONY: clean mrproper

clean:
	rm -rf $(BUILD)/* 

mrproper: clean
	rm -rf $(BUILD)/
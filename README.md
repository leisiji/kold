# kold - Kernel Object Linker/Loader for ARM

A tool to reduce kernel module code size and speed up `insmod` by pre-applying local relocations at build time.

## Overview

When building kernel modules, the linker (`ld -r`) is used to produce a relocatable output file. However, `ld -r` **does not perform cross-file deduplication** of local symbols. This means that many kernel module (`.ko`) files end up containing:

- Local symbols that reference addresses within the same section
- Relocation entries that could have been resolved at link time, but weren't
- Unnecessary overhead in both file size and runtime relocation processing

`kold` solves this by:
1. Parsing the ELF file to identify local relocations that target symbols in the same section
2. Applying these relocations directly to the code (modifying instructions in-place)
3. Removing the now-unnecessary relocation entries from the relocation sections
4. Producing an optimized ELF file with smaller code size and fewer relocations

## Key Benefits

### 1. Reduced Code Size
By removing processed relocation entries from `.rel.text`, `.rel.init.text`, and `.rel.exit.text` sections, the resulting `.ko` file is smaller.

### 2. Faster `insmod`
Fewer relocations to process at module load time means `insmod` completes faster, which is especially important for embedded systems with limited CPU resources.

### 3. Build-Time Optimization
All processing happens at build time; there is zero runtime overhead.

## The Problem: `ld -r` and Local Symbols

When compiling kernel modules, the build process typically involves:

1. Compiling individual C files to `.o` files
2. Using `ld -r` to combine them into a single relocatable object
3. Processing the result into the final `.ko` module

The `ld -r` step produces a relocatable output, meaning it preserves relocation information rather than resolving it. For local symbols (symbols that are private to the module), this creates unnecessary overhead:

```
Before kold:
- Code section contains placeholder instructions
- Relocation section contains entries for every local call
- At insmod: kernel resolves each local relocation

After kold:
- Code section contains correctly-patched instructions
- Relocation section no longer contains resolved entries
- At insmod: fewer relocations to process
```

## Building

```bash
gcc -o kold kold.c
```

Or use the provided object file if available:
```bash
make kold
```

## Usage

```bash
kold <input.o> -o <output.o>
```

### Arguments

- `<input.o>`: Input ELF object file (32-bit ARM)
- `-o <output.o>`: Output file path (required)

### Example

```bash
# Process a kernel module
kold simplefs.ko -o simplefs_optimized.ko

# Process an object file in-place
kold module.o -o module.o
```

## Supported Relocation Types

- `R_ARM_THM_CALL` (10): Thumb-2 BL/BLX immediate instruction
- `R_ARM_THM_JUMP24` (30): Thumb-2 B.W immediate instruction

## Supported Sections

- `.text` / `.rel.text`
- `.init.text` / `.rel.init.text`
- `.exit.text` / `.rel.exit.text`

## Limitations

- Only supports 32-bit ARM ELF files (`ELFCLASS32`)
- Only processes ARM Thumb-2 call/jump relocations
- Requires well-formed input ELF files with valid symbol tables
- Output file may have different section layout than input (shrunk relocation sections)

## Files

- `kold.c`: Main source code
- `kold`: Compiled binary
- `remove_unref_sym.sh`: Helper script to remove unreferenced symbols

## License

This tool is provided as-is for kernel development purposes.

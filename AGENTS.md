# AGENTS.md

This file provides guidance to AI coding assistants (Claude Code, Gemini Code Assist, etc.) when working with code in this repository.

**Note**: Also check `AGENTS.local.md` for additional local development instructions when present.

## Project Overview

This is a network address extension for VillageSQL (a MySQL-compatible database) that provides PostgreSQL-compatible network address types (INET, CIDR, MACADDR, MACADDR8). The extension is built as a shared library (.so) packaged in a VEB (VillageSQL Extension Bundle) archive for installation.

## Build System

- **Configure**: `mkdir build && cd build && cmake .. -DVillageSQL_BUILD_DIR=/path/to/villagesql/build`
- **Build**: `make` (creates VEB package automatically)
- **Install**: `make install` (installs VEB to VillageSQL's `veb_output_directory`)

The build process:
1. Uses CMake with `FindVillageSQL.cmake` to locate the VillageSQL Extension SDK in the build tree
2. Compiles C++ source files into shared library `network_address.so`
3. Packages library with `manifest.json` into `vsql-network-address.veb` archive using `VEF_CREATE_VEB()`

**Requirements:**
- VillageSQL build directory
- OpenSSL development libraries
- C++17 compiler

## Architecture

**Core Components:**
- `src/network_address.cc` - Complete implementation of all network address types and functions (no separate header files)
- `cmake/FindVillageSQL.cmake` - CMake module to locate the VillageSQL SDK

**Network Address Types:**
- **INET**: IP addresses (IPv4/IPv6) with optional netmask, allows host bits to be set
- **CIDR**: Network addresses with strict validation (host bits must be zero)
- **MACADDR**: 6-byte MAC addresses (IEEE 802 MAC-48)
- **MACADDR8**: 8-byte MAC addresses (EUI-64 format)

**Available Functions:**
Each type provides:
- **Conversion**: `{type}_from_string()`, `{type}_to_string()`, `{type}_compare()`
- **Network Functions** (INET/CIDR only):
  - Simple extractors: `inet_family()`, `inet_masklen()`, `inet_host()`, `inet_text()`
  - Mask calculations: `inet_netmask()`, `inet_hostmask()`, `inet_broadcast()`, `inet_network()`
  - Modifiers: `inet_set_masklen()`, `cidr_set_masklen()`, `macaddr_trunc()`
  - Formatting: `inet_abbrev()`, `cidr_abbrev()`

**Internal Storage:**
- IPv4Network: 7 bytes (4-byte address + 1-byte netmask + 1-byte family + 1-byte flags)
- IPv6Network: 19 bytes (16-byte address + 1-byte netmask + 1-byte family + 1-byte flags)
- MacAddr: 6 bytes
- MacAddr8: 8 bytes

**Dependencies:**
- VillageSQL Extension SDK
- OpenSSL (for cryptographic operations)

## Development Conventions

**Coding Style:**
- **File Naming:** Lowercase with underscores (e.g., `network_address.cc`)
- **Variable Naming:** Lowercase with underscores (e.g., `buffer_size`)
- **Function Naming:** Lowercase with underscores (e.g., `encode_cidr`)
- **Namespace:** Functions are in the `network_address` namespace

**API Conventions:**
- Encode functions return `bool` (true = error, false = success)
- Decode functions return `bool` (true = error, false = success)
- All functions use `size_t` for sizes and lengths (not `uint64_t` or `int`)
- String output uses C-style: `char *to, size_t to_size, size_t *to_length`
- Comparison functions return `int` (-1, 0, or 1)

## Testing

The extension includes a comprehensive test suite using the MySQL Test Runner (MTR) framework:
- **Test Location**: `test/` directory with `.test` files and expected `.result` files

**Default: Using installed VEB**

This method assumes you have successfully run `make install` to install the VEB to your veb_dir:

```bash
cd /path/to/mysql-test
perl mysql-test-run.pl --suite=/path/to/vsql-network-address/test
```

**Alternative: Using a specific VEB file**

Use this to test a specific VEB build without installing it first:

```bash
cd /path/to/mysql-test
VSQL_NETWORK_ADDRESS_VEB=/path/to/vsql-network-address/build/vsql-network-address.veb \
  perl mysql-test-run.pl --suite=/path/to/vsql-network-address/test
```

**Test Setup Pattern:**
All test files include this setup at the beginning to support both testing methods:

```sql
# Setup: Copy VEB to veb_dir if VSQL_NETWORK_ADDRESS_VEB is set, then install extension
--let $veb_dest = `SELECT CONCAT(@@veb_dir, '/vsql-network-address.veb')`
if ($VSQL_NETWORK_ADDRESS_VEB) {
  --error 0,1
  --remove_file $veb_dest
  --copy_file $VSQL_NETWORK_ADDRESS_VEB $veb_dest
}
INSTALL EXTENSION 'vsql-network-address';
```

## Extension Installation

The VEB package contains:
- `manifest.json` - Extension metadata
- `lib/network_address.so` - Shared library with all implementations

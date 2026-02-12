# VillageSQL Network Address Extension

A comprehensive network address extension for VillageSQL Server providing PostgreSQL-compatible network address types. This extension adds support for INET, CIDR, MACADDR, and MACADDR8 data types with conversion, validation, and comparison capabilities.

## Features

- **Complete Network Address Support**: IPv4, IPv6, MAC addresses (6-byte and 8-byte EUI-64)
- **PostgreSQL Compatibility**: Drop-in replacement for PostgreSQL's network address types
- **Four Custom Types**: INET (IP with optional netmask), CIDR (strict network addresses), MACADDR (6-byte MAC), MACADDR8 (8-byte MAC)
- **Validation & Conversion**: Comprehensive parsing and formatting for all address types
- **Optimized C++ implementation** with binary storage

## Installation

### Option 1: Install Pre-built VEB Package
1. Download the `vsql-network-address.veb` package from releases
2. Install the VEB package to your VillageSQL instance

### Option 2: Build from Source

#### Prerequisites
- VillageSQL build directory
- CMake 3.16 or higher
- C++17 compatible compiler
- OpenSSL development libraries

📚 **Full Documentation**: Visit [villagesql.com/docs](https://villagesql.com/docs) for comprehensive guides on building extensions, architecture details, and more.

#### Build Instructions
1. Clone the repository:
   ```bash
   git clone https://github.com/villagesql/vsql-network-address.git
   cd vsql-network-address
   ```

2. Create build directory and build the extension:

   **Linux:**
   ```bash
   mkdir -p build
   cd build
   cmake .. -DVillageSQL_BUILD_DIR=$HOME/build/villagesql
   make -j $(($(getconf _NPROCESSORS_ONLN) - 2))
   ```

   **macOS:**
   ```bash
   mkdir -p build
   cd build
   cmake .. -DVillageSQL_BUILD_DIR=~/build/villagesql
   make -j $(($(getconf _NPROCESSORS_ONLN) - 2))
   ```

   This will create the `vsql-network-address.veb` package in the build directory and automatically configure the VEB install directory to point to VillageSQL's `veb_output_directory`.

3. Install the VEB package to your VillageSQL instance:
   ```bash
   make install
   ```

## Usage

After installation, the extension provides the following types and functions.

### Network Address Types

#### INET Type
IP addresses (IPv4 or IPv6) with optional netmask. Allows host bits to be set.

```sql
-- Create table with INET column
CREATE TABLE hosts (
    id INT PRIMARY KEY,
    ip_address INET
);

-- Insert various INET formats (IPv4 and IPv6)
INSERT INTO hosts VALUES (1, inet_from_string('192.168.1.5'));
INSERT INTO hosts VALUES (2, inet_from_string('192.168.1.0/24'));
INSERT INTO hosts VALUES (3, inet_from_string('2001:db8::1'));
INSERT INTO hosts VALUES (4, inet_from_string('2001:db8::1/64'));
INSERT INTO hosts VALUES (5, inet_from_string('fe80::1'));

-- Query and display
SELECT id, inet_to_string(ip_address) FROM hosts;
```

#### CIDR Type
Network addresses with strict validation - requires host bits to be zero.

```sql
-- Create table with CIDR column
CREATE TABLE networks (
    id INT PRIMARY KEY,
    network CIDR
);

-- Insert valid network addresses (IPv4 and IPv6)
INSERT INTO networks VALUES (1, cidr_from_string('192.168.1.0/24'));
INSERT INTO networks VALUES (2, cidr_from_string('10.0.0.0/8'));
INSERT INTO networks VALUES (3, cidr_from_string('2001:db8::/32'));
INSERT INTO networks VALUES (4, cidr_from_string('fe80::/64'));

-- This would fail: '192.168.1.5/24' (host bits set)
-- This would also fail: '2001:db8::1/64' (host bits set)
```

#### MACADDR Type
6-byte MAC addresses (IEEE 802 MAC-48).

```sql
-- Create table with MACADDR column
CREATE TABLE devices (
    id INT PRIMARY KEY,
    mac_address MACADDR
);

-- Insert MAC addresses (various formats supported)
INSERT INTO devices VALUES (1, macaddr_from_string('08:00:2b:01:02:03'));
INSERT INTO devices VALUES (2, macaddr_from_string('08-00-2b-01-02-04'));

-- Query
SELECT id, macaddr_to_string(mac_address) FROM devices;
```

#### MACADDR8 Type
8-byte MAC addresses (EUI-64 format).

```sql
-- Create table with MACADDR8 column
CREATE TABLE modern_devices (
    id INT PRIMARY KEY,
    mac_address MACADDR8
);

-- Insert EUI-64 MAC addresses
INSERT INTO modern_devices VALUES (1, macaddr8_from_string('08:00:2b:01:02:03:04:05'));
```

### Conversion Functions

Each type provides three core functions:

**INET Functions:**
- `inet_from_string(string)` - Parse string to INET
- `inet_to_string(inet)` - Format INET as string
- `inet_compare(inet, inet)` - Compare two INET values (-1, 0, or 1)

**CIDR Functions:**
- `cidr_from_string(string)` - Parse string to CIDR
- `cidr_to_string(cidr)` - Format CIDR as string
- `cidr_compare(cidr, cidr)` - Compare two CIDR values

**MACADDR Functions:**
- `macaddr_from_string(string)` - Parse string to MACADDR
- `macaddr_to_string(macaddr)` - Format MACADDR as string
- `macaddr_compare(macaddr, macaddr)` - Compare two MACADDR values

**MACADDR8 Functions:**
- `macaddr8_from_string(string)` - Parse string to MACADDR8
- `macaddr8_to_string(macaddr8)` - Format MACADDR8 as string
- `macaddr8_compare(macaddr8, macaddr8)` - Compare two MACADDR8 values

### Network Manipulation Functions

#### Simple Extractors
Extract information from INET values:

- `inet_family(inet)` - Returns address family (4 for IPv4, 6 for IPv6)
- `inet_masklen(inet)` - Returns netmask length as integer
- `inet_host(inet)` - Returns IP address without netmask as string
- `inet_text(inet)` - Returns IP address with netmask as string

```sql
-- IPv4 examples
SELECT inet_family(inet_from_string('192.168.1.5/24'));    -- Returns: 4
SELECT inet_masklen(inet_from_string('192.168.1.5/24'));   -- Returns: 24
SELECT inet_host(inet_from_string('192.168.1.5/24'));      -- Returns: '192.168.1.5'
SELECT inet_text(inet_from_string('192.168.1.5/24'));      -- Returns: '192.168.1.5/24'

-- IPv6 examples
SELECT inet_family(inet_from_string('2001:db8::1/64'));    -- Returns: 6
SELECT inet_masklen(inet_from_string('2001:db8::1/64'));   -- Returns: 64
SELECT inet_host(inet_from_string('2001:db8::1/64'));      -- Returns: '2001:0db8:0000:0000:0000:0000:0000:0001'
SELECT inet_text(inet_from_string('2001:db8::1/64'));      -- Returns: '2001:0db8:0000:0000:0000:0000:0000:0001/64'
```

#### Mask Calculations
Calculate network masks and addresses:

- `inet_netmask(inet)` - Returns netmask for the network as INET
- `inet_hostmask(inet)` - Returns host mask (inverse of netmask) as INET
- `inet_broadcast(inet)` - Returns broadcast address for the network as INET
- `inet_network(inet)` - Returns network address (host bits zeroed) as CIDR

```sql
-- IPv4 examples
SELECT inet_to_string(inet_netmask(inet_from_string('192.168.1.5/24')));    -- Returns: '255.255.255.0/32'
SELECT inet_to_string(inet_hostmask(inet_from_string('192.168.1.5/24')));   -- Returns: '0.0.0.255/32'
SELECT inet_to_string(inet_broadcast(inet_from_string('192.168.1.5/24')));  -- Returns: '192.168.1.255/32'
SELECT cidr_to_string(inet_network(inet_from_string('192.168.1.5/24')));    -- Returns: '192.168.1.0/24'

-- IPv6 examples
SELECT inet_to_string(inet_netmask(inet_from_string('2001:db8::1/64')));    -- Returns: 'ffff:ffff:ffff:ffff:0000:0000:0000:0000'
SELECT inet_to_string(inet_hostmask(inet_from_string('2001:db8::1/64')));   -- Returns: '0000:0000:0000:0000:ffff:ffff:ffff:ffff'
SELECT inet_to_string(inet_broadcast(inet_from_string('2001:db8::1/64')));  -- Returns: '2001:0db8:0000:0000:ffff:ffff:ffff:ffff/64'
SELECT cidr_to_string(inet_network(inet_from_string('2001:db8::1/64')));    -- Returns: '2001:0db8:0000:0000:0000:0000:0000:0000/64'
```

#### Modifiers
Modify network addresses:

- `inet_set_masklen(inet, integer)` - Changes netmask length without modifying address bits
- `cidr_set_masklen(cidr, integer)` - Changes netmask length and zeros host bits
- `macaddr_trunc(macaddr)` - Zeroes last 3 bytes (keeps OUI only)

```sql
SELECT inet_to_string(inet_set_masklen(inet_from_string('192.168.1.5/24'), 16));  -- Returns: '192.168.1.5/16'
SELECT cidr_to_string(cidr_set_masklen(cidr_from_string('192.168.1.0/24'), 16));  -- Returns: '192.168.0.0/16'
SELECT macaddr_to_string(macaddr_trunc(macaddr_from_string('08:00:2b:01:02:03'))); -- Returns: '08:00:2b:00:00:00'
```

#### Formatting (Abbreviation)
Format addresses in abbreviated form:

- `inet_abbrev(inet)` - Abbreviated format (omits /32 for single hosts)
- `cidr_abbrev(cidr)` - Abbreviated format showing minimal significant octets

```sql
SELECT inet_abbrev(inet_from_string('192.168.1.5/32'));   -- Returns: '192.168.1.5'
SELECT inet_abbrev(inet_from_string('192.168.1.5/24'));   -- Returns: '192.168.1.5/24'
SELECT cidr_abbrev(cidr_from_string('10.0.0.0/8'));       -- Returns: '10/8'
SELECT cidr_abbrev(cidr_from_string('192.168.0.0/16'));   -- Returns: '192.168/16'
```

### Supported Formats

**IPv4:**
- Standard: `192.168.1.5`
- With netmask: `192.168.1.0/24`

**IPv6:**
- Standard: `2001:db8::1`
- With prefix: `2001:db8::/32`
- Compressed notation: `::1` (loopback), `::` (all zeros)
- Full notation: `2001:0db8:0000:0000:0000:0000:0000:0001`
- Link-local: `fe80::1`

**MAC Addresses:**
- Colon notation: `08:00:2b:01:02:03`
- Hyphen notation: `08-00-2b-01-02-03`
- Cisco notation: `08002b:010203`

### Indexing and Sorting

All network address types support indexing and sorting:

```sql
-- Create indexes
CREATE INDEX idx_ip ON hosts(ip_address);
CREATE UNIQUE INDEX idx_mac ON devices(mac_address);

-- Sort by IP address
SELECT inet_to_string(ip_address) FROM hosts ORDER BY ip_address;

-- Sort by MAC address
SELECT macaddr_to_string(mac_address) FROM devices ORDER BY mac_address;
```

## Testing

The extension includes a comprehensive test suite using the MySQL Test Runner (MTR) framework:
- **Test Location**: `test/` directory with `.test` files and expected `.result` files

**Default: Using installed VEB**

This method assumes you have successfully run `make install` to install the VEB to your veb_dir:

**Linux:**
```bash
cd $HOME/build/villagesql/mysql-test
perl mysql-test-run.pl --suite=/path/to/vsql-network-address/test
```

**macOS:**
```bash
cd ~/build/villagesql/mysql-test
perl mysql-test-run.pl --suite=/path/to/vsql-network-address/test
```

**Alternative: Using a specific VEB file**

Use this to test a specific VEB build without installing it first:

**Linux:**
```bash
cd $HOME/build/villagesql/mysql-test
VSQL_NETWORK_ADDRESS_VEB=/path/to/vsql-network-address/build/vsql-network-address.veb \
  perl mysql-test-run.pl --suite=/path/to/vsql-network-address/test
```

**macOS:**
```bash
cd ~/build/villagesql/mysql-test
VSQL_NETWORK_ADDRESS_VEB=/path/to/vsql-network-address/build/vsql-network-address.veb \
  perl mysql-test-run.pl --suite=/path/to/vsql-network-address/test
```

Test coverage includes:
- IPv4 and IPv6 address validation and parsing
- IPv6 compressed notation (`::`) support
- CIDR network validation (host bits checking)
- All network manipulation functions (extractors, modifiers, formatters)
- CREATE, ALTER, and CTAS operations
- Indexing and sorting
- NULL handling and constraints

## Development

### Project Structure
```
vsql-network-address/
├── src/
│   └── network_address.cc      # Core network address implementation
├── cmake/
│   └── FindVillageSQL.cmake    # CMake module to locate VillageSQL SDK
├── test/                       # MTR test suite
│   ├── t/                      # Test files
│   └── r/                      # Expected results
├── manifest.json               # VEB package manifest
└── CMakeLists.txt              # Build configuration
```

### Build Targets
- `make` - Build the extension and create the `vsql-network-address.veb` package
- `make install` - Install the VEB package to the specified directory

## Reporting Bugs and Requesting Features

If you encounter a bug or have a feature request, please open an [issue](./issues) using GitHub Issues. Please provide as much detail as possible, including:

* A clear and descriptive title
* A detailed description of the issue or feature request
* Steps to reproduce the bug (if applicable)
* Your environment details (OS, VillageSQL version, etc.)

## License

License information can be found in the [LICENSE](./LICENSE) file.

## Contributing

VillageSQL welcomes contributions from the community. Please ensure all tests pass before submitting pull requests:

1. Build the extension:

   **Linux:**
   ```bash
   mkdir -p build && cd build
   cmake .. -DVillageSQL_BUILD_DIR=$HOME/build/villagesql
   make -j $(($(getconf _NPROCESSORS_ONLN) - 2)) && make install
   ```

   **macOS:**
   ```bash
   mkdir -p build && cd build
   cmake .. -DVillageSQL_BUILD_DIR=~/build/villagesql
   make -j $(($(getconf _NPROCESSORS_ONLN) - 2)) && make install
   ```

2. Run the test suite:

   **Linux:**
   ```bash
   cd $HOME/build/villagesql/mysql-test
   perl mysql-test-run.pl --suite=/path/to/vsql-network-address/test
   ```

   **macOS:**
   ```bash
   cd ~/build/villagesql/mysql-test
   perl mysql-test-run.pl --suite=/path/to/vsql-network-address/test
   ```

3. Submit your pull request with a clear description of changes

## Contact

Join the VillageSQL community:

* File a [bug or issue](./issues) and we will review
* Start a discussion in the project [discussions](./discussions)
* Join the [Discord channel](https://discord.gg/KSr6whd3Fr)

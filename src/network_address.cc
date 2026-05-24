/* Copyright (c) 2025 VillageSQL Contributors
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <villagesql/vsql.h>

#include <cassert>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <stdio.h>
#include <string>

using namespace ::vsql;

namespace network_address {

// Data structure definitions for network address types

// IPv4 network address structure (7 bytes total)
struct IPv4Network {
  uint32_t address;  // 4 bytes - network byte order
  uint8_t netmask;   // 1 byte - CIDR prefix length
  uint8_t family;    // 1 byte - address family (2 for IPv4)
  uint8_t flags;     // 1 byte - type flags (CIDR vs INET)
};

// IPv6 network address structure (19 bytes total)
struct IPv6Network {
  uint8_t address[16]; // 16 bytes - IPv6 address
  uint8_t netmask;     // 1 byte - CIDR prefix length
  uint8_t family;      // 1 byte - address family (10 for IPv6)
  uint8_t flags;       // 1 byte - type flags (CIDR vs INET)
};

// MAC address structure (6 bytes)
struct MacAddr {
  uint8_t address[6];  // 6 bytes - MAC address
};

// Extended MAC address structure (8 bytes)
struct MacAddr8 {
  uint8_t address[8];  // 8 bytes - EUI-64 MAC address
};

// Constants
static constexpr uint8_t ADDR_FLAG_CIDR = 0x01;  // Strict CIDR validation
static constexpr uint8_t ADDR_FLAG_INET = 0x02;  // INET allows host bits
static constexpr uint8_t AF_INET_VAL = 2;        // IPv4 family
static constexpr uint8_t AF_INET6_VAL = 10;      // IPv6 family
static constexpr uint8_t IPV4_MAX_PREFIXLEN = 32;
static constexpr uint8_t IPV6_MAX_PREFIXLEN = 128;

// Maximum string lengths for display
static constexpr size_t kMaxIPv4String = 18;   // xxx.xxx.xxx.xxx/32
static constexpr size_t kMaxIPv6String = 44;   // full IPv6 with /128 + null
static constexpr size_t kMaxMacAddrString = 17; // xx:xx:xx:xx:xx:xx
static constexpr size_t kMaxMacAddr8String = 23; // xx:xx:xx:xx:xx:xx:xx:xx

// Helper functions for parsing network addresses

// Parse IPv4 address string "192.168.1.1" into uint32_t
bool parse_ipv4_address(const char* addr_str, uint32_t* address) {
  unsigned int a, b, c, d;
  if (sscanf(addr_str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
    return false;
  }
  if (a > 255 || b > 255 || c > 255 || d > 255) {
    return false;
  }
  // Store in network byte order
  *address = (a << 24) | (b << 16) | (c << 8) | d;
  return true;
}

// Format IPv4 address from uint32_t to string
void format_ipv4_address(uint32_t address, char* buffer, size_t buffer_size) {
  snprintf(buffer, buffer_size, "%u.%u.%u.%u",
           (address >> 24) & 0xFF,
           (address >> 16) & 0xFF,
           (address >> 8) & 0xFF,
           address & 0xFF);
}

// Parse IPv6 address string with :: compression support
bool parse_ipv6_address(const char* addr_str, uint8_t* address) {
  if (addr_str == nullptr || address == nullptr) {
    return false;
  }

  // Initialize address to zeros
  memset(address, 0, 16);

  // Find :: if present (marks compression point)
  const char *double_colon = strstr(addr_str, "::");

  if (double_colon != nullptr) {
    // Parse left side of ::
    int left_parts = 0;
    uint16_t left_values[8];

    if (double_colon != addr_str) {
      // There are parts before ::
      std::string left_str(addr_str, double_colon - addr_str);
      const char *p = left_str.c_str();
      while (*p && left_parts < 8) {
        char *end;
        unsigned long val = strtoul(p, &end, 16);
        if (val > 0xFFFF || p == end) {
          return false;
        }
        left_values[left_parts++] = static_cast<uint16_t>(val);
        if (*end == ':') {
          p = end + 1;
        } else if (*end == '\0') {
          break;
        } else {
          return false;
        }
      }
    }

    // Parse right side of ::
    int right_parts = 0;
    uint16_t right_values[8];
    const char *right_start = double_colon + 2;

    if (*right_start != '\0') {
      const char *p = right_start;
      while (*p && right_parts < 8) {
        char *end;
        unsigned long val = strtoul(p, &end, 16);
        if (val > 0xFFFF || p == end) {
          return false;
        }
        right_values[right_parts++] = static_cast<uint16_t>(val);
        if (*end == ':') {
          p = end + 1;
        } else if (*end == '\0') {
          break;
        } else {
          return false;
        }
      }
    }

    // Validate total parts don't exceed 8
    if (left_parts + right_parts > 7) {
      return false;
    }

    // Fill in the address
    for (int i = 0; i < left_parts; i++) {
      address[i * 2] = (left_values[i] >> 8) & 0xFF;
      address[i * 2 + 1] = left_values[i] & 0xFF;
    }

    int right_start_index = 8 - right_parts;
    for (int i = 0; i < right_parts; i++) {
      int idx = right_start_index + i;
      address[idx * 2] = (right_values[i] >> 8) & 0xFF;
      address[idx * 2 + 1] = right_values[i] & 0xFF;
    }

  } else {
    // No :: compression, must have exactly 8 parts
    uint16_t parts[8];
    const char *p = addr_str;
    int part_count = 0;

    while (*p && part_count < 8) {
      char *end;
      unsigned long val = strtoul(p, &end, 16);
      if (val > 0xFFFF || p == end) {
        return false;
      }
      parts[part_count++] = static_cast<uint16_t>(val);
      if (*end == ':') {
        p = end + 1;
      } else if (*end == '\0') {
        break;
      } else {
        return false;
      }
    }

    if (part_count != 8) {
      return false;
    }

    for (int i = 0; i < 8; i++) {
      address[i * 2] = (parts[i] >> 8) & 0xFF;
      address[i * 2 + 1] = parts[i] & 0xFF;
    }
  }

  return true;
}

// Format IPv6 address to string
void format_ipv6_address(const uint8_t* address, char* buffer, size_t buffer_size) {
  snprintf(buffer, buffer_size, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
           address[0], address[1], address[2], address[3],
           address[4], address[5], address[6], address[7],
           address[8], address[9], address[10], address[11],
           address[12], address[13], address[14], address[15]);
}

// Parse MAC address string "08:00:2b:01:02:03"
bool parse_mac_address(const char* mac_str, uint8_t* address, int expected_bytes) {
  if (mac_str == nullptr || address == nullptr) {
    return false;
  }

  std::string cleaned;
  cleaned.reserve(expected_bytes * 2);

  for (const char *cursor = mac_str; *cursor != '\0'; ++cursor) {
    unsigned char ch = static_cast<unsigned char>(*cursor);
    if (std::isxdigit(ch)) {
      cleaned.push_back(static_cast<char>(std::tolower(ch)));
    } else if (ch == ':' || ch == '-' || ch == '.') {
      continue; // Accept common separators
    } else {
      return false; // Reject unexpected characters early
    }
  }

  if (static_cast<int>(cleaned.size()) != expected_bytes * 2) {
    return false;
  }

  for (int i = 0; i < expected_bytes; ++i) {
    unsigned int value = 0;
    if (sscanf(cleaned.substr(i * 2, 2).c_str(), "%02x", &value) != 1) {
      return false;
    }
    address[i] = static_cast<uint8_t>(value & 0xFF);
  }

  return true;
}

// Format MAC address to string
void format_mac_address(const uint8_t* address, char* buffer, size_t buffer_size, int bytes) {
  if (bytes == 6) {
    snprintf(buffer, buffer_size, "%02x:%02x:%02x:%02x:%02x:%02x",
             address[0], address[1], address[2], address[3], address[4], address[5]);
  } else if (bytes == 8) {
    snprintf(buffer, buffer_size, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
             address[0], address[1], address[2], address[3],
             address[4], address[5], address[6], address[7]);
  }
}

// Validate CIDR network address (no host bits set)
bool validate_cidr_network(uint32_t address, uint8_t netmask) {
  if (netmask > IPV4_MAX_PREFIXLEN) return false;
  if (netmask == 0) return true;

  uint32_t mask = ~((1u << (IPV4_MAX_PREFIXLEN - netmask)) - 1);
  return (address & ~mask) == 0;
}

// Validate IPv6 CIDR network address (no host bits set)
bool validate_cidr_network_ipv6(const uint8_t *address, uint8_t netmask) {
  if (netmask > IPV6_MAX_PREFIXLEN)
    return false;
  if (netmask == 0)
    return true;

  // Check that all host bits are zero
  int full_bytes = netmask / 8;
  int remaining_bits = netmask % 8;

  // Check partial byte if exists
  if (remaining_bits > 0) {
    uint8_t mask = 0xFF << (8 - remaining_bits);
    if ((address[full_bytes] & ~mask) != 0) {
      return false;
    }
    full_bytes++;
  }

  // Check remaining bytes are all zero
  for (int i = full_bytes; i < 16; i++) {
    if (address[i] != 0) {
      return false;
    }
  }

  return true;
}

// Encoding/decoding functions for each type

namespace {

bool MarkInvalid(size_t *length) {
  if (length != nullptr) {
    *length = 0;
  }
  return true;
}

} // namespace

bool encode_cidr(unsigned char *buffer, size_t buffer_size, const char *from, size_t from_len, size_t *length) {
  if (buffer_size < sizeof(IPv4Network) || nullptr == buffer) {
    return true;
  }

  std::string from_str(from, from_len);
  char addr_str[64];
  int netmask;

  if (sscanf(from_str.c_str(), "%63[^/]/%d", addr_str, &netmask) != 2) {
    return MarkInvalid(length); // Parse error
  }

  // Try IPv4 first
  IPv4Network net4;
  if (parse_ipv4_address(addr_str, &net4.address)) {
    if (netmask < 0 || netmask > IPV4_MAX_PREFIXLEN) {
      return MarkInvalid(length);
    }

    net4.netmask = static_cast<uint8_t>(netmask);
    net4.family = AF_INET_VAL;
    net4.flags = ADDR_FLAG_CIDR;

    // CIDR requires strict network validation
    if (!validate_cidr_network(net4.address, net4.netmask)) {
      return MarkInvalid(length); // Invalid network address for CIDR
    }

    memcpy(buffer, &net4, sizeof(IPv4Network));
    *length = sizeof(IPv4Network);
    return false;
  }

  // Try IPv6
  if (buffer_size < sizeof(IPv6Network)) {
    return true;
  }

  IPv6Network net6;
  if (parse_ipv6_address(addr_str, net6.address)) {
    if (netmask < 0 || netmask > IPV6_MAX_PREFIXLEN) {
      return MarkInvalid(length);
    }

    net6.netmask = static_cast<uint8_t>(netmask);
    net6.family = AF_INET6_VAL;
    net6.flags = ADDR_FLAG_CIDR;

    // CIDR requires strict network validation
    if (!validate_cidr_network_ipv6(net6.address, net6.netmask)) {
      return MarkInvalid(length); // Invalid network address for CIDR
    }

    memcpy(buffer, &net6, sizeof(IPv6Network));
    *length = sizeof(IPv6Network);
    return false;
  }

  return MarkInvalid(length); // Invalid address format
}

bool decode_cidr(const unsigned char *buffer, size_t buffer_size, char *to, size_t to_size, size_t *to_length) {
  if (buffer_size < sizeof(IPv4Network) || nullptr == buffer || nullptr == to) {
    return true;
  }

  // Check family to determine which structure to use
  // For IPv4: family is at byte 5 (4 bytes address + 1 byte netmask)
  // For IPv6: family is at byte 17 (16 bytes address + 1 byte netmask)
  uint8_t family = buffer[5]; // Try IPv4 first

  if (family == AF_INET_VAL && buffer_size >= sizeof(IPv4Network)) {
    IPv4Network net;
    memcpy(&net, buffer, sizeof(IPv4Network));

    char addr_str[32];
    format_ipv4_address(net.address, addr_str, sizeof(addr_str));

    char result[64];
    snprintf(result, sizeof(result), "%s/%u", addr_str,
             (unsigned int)net.netmask);

    size_t len = strlen(result);
    if (len + 1 > to_size) return true;
    strcpy(to, result);
    *to_length = len;
    return false;

  } else if (buffer_size >= sizeof(IPv6Network)) {
    // Check if it's IPv6
    uint8_t ipv6_family = buffer[17]; // Family byte for IPv6
    if (ipv6_family == AF_INET6_VAL) {
      IPv6Network net;
      memcpy(&net, buffer, sizeof(IPv6Network));

      char addr_str[kMaxIPv6String];
      format_ipv6_address(net.address, addr_str, sizeof(addr_str));

      char result[kMaxIPv6String];
      snprintf(result, sizeof(result), "%s/%u", addr_str,
               (unsigned int)net.netmask);

      size_t len = strlen(result);
      if (len + 1 > to_size) return true;
      strcpy(to, result);
      *to_length = len;
      return false;
    }
  }

  return true; // Unknown family
}

bool encode_inet(unsigned char *buffer, size_t buffer_size, const char *from, size_t from_len, size_t *length) {
  if (buffer_size < sizeof(IPv4Network) || nullptr == buffer) {
    return true;
  }

  std::string from_str(from, from_len);
  char addr_str[64];
  int netmask = -1; // Will be set based on address family

  // Try parsing with netmask first, then without
  if (sscanf(from_str.c_str(), "%63[^/]/%d", addr_str, &netmask) != 2) {
    // No netmask specified, use the whole string as address
    strncpy(addr_str, from_str.c_str(), sizeof(addr_str) - 1);
    addr_str[sizeof(addr_str) - 1] = '\0';
  }

  // Try IPv4 first
  IPv4Network net4;
  if (parse_ipv4_address(addr_str, &net4.address)) {
    if (netmask == -1) {
      netmask = IPV4_MAX_PREFIXLEN; // Default for IPv4
    }
    if (netmask < 0 || netmask > IPV4_MAX_PREFIXLEN) {
      return MarkInvalid(length);
    }

    net4.netmask = static_cast<uint8_t>(netmask);
    net4.family = AF_INET_VAL;
    net4.flags = ADDR_FLAG_INET;

    memcpy(buffer, &net4, sizeof(IPv4Network));
    *length = sizeof(IPv4Network);
    return false;
  }

  // Try IPv6
  if (buffer_size < sizeof(IPv6Network)) {
    return true;
  }

  IPv6Network net6;
  if (parse_ipv6_address(addr_str, net6.address)) {
    if (netmask == -1) {
      netmask = IPV6_MAX_PREFIXLEN; // Default for IPv6
    }
    if (netmask < 0 || netmask > IPV6_MAX_PREFIXLEN) {
      return MarkInvalid(length);
    }

    net6.netmask = static_cast<uint8_t>(netmask);
    net6.family = AF_INET6_VAL;
    net6.flags = ADDR_FLAG_INET;

    memcpy(buffer, &net6, sizeof(IPv6Network));
    *length = sizeof(IPv6Network);
    return false;
  }

  return MarkInvalid(length); // Invalid address format
}

bool decode_inet(const unsigned char *buffer, size_t buffer_size, char *to, size_t to_size, size_t *to_length) {
  if (buffer_size < sizeof(IPv4Network) || nullptr == buffer || nullptr == to) {
    return true;
  }

  // Check family to determine which structure to use
  uint8_t family = buffer[5]; // Try IPv4 first

  if (family == AF_INET_VAL && buffer_size >= sizeof(IPv4Network)) {
    IPv4Network net;
    memcpy(&net, buffer, sizeof(IPv4Network));

    char addr_str[32];
    format_ipv4_address(net.address, addr_str, sizeof(addr_str));

    char result[64];
    if (net.netmask == IPV4_MAX_PREFIXLEN) {
      // Don't show /32 for host addresses
      snprintf(result, sizeof(result), "%s", addr_str);
    } else {
      snprintf(result, sizeof(result), "%s/%u", addr_str,
               (unsigned int)net.netmask);
    }

    size_t len = strlen(result);
    if (len + 1 > to_size) return true;
    strcpy(to, result);
    *to_length = len;
    return false;

  } else if (buffer_size >= sizeof(IPv6Network)) {
    // Check if it's IPv6
    uint8_t ipv6_family = buffer[17]; // Family byte for IPv6
    if (ipv6_family == AF_INET6_VAL) {
      IPv6Network net;
      memcpy(&net, buffer, sizeof(IPv6Network));

      char addr_str[kMaxIPv6String];
      format_ipv6_address(net.address, addr_str, sizeof(addr_str));

      char result[kMaxIPv6String];
      if (net.netmask == IPV6_MAX_PREFIXLEN) {
        // Don't show /128 for host addresses
        snprintf(result, sizeof(result), "%s", addr_str);
      } else {
        snprintf(result, sizeof(result), "%s/%u", addr_str,
                 (unsigned int)net.netmask);
      }

      size_t len = strlen(result);
      if (len + 1 > to_size) return true;
      strcpy(to, result);
      *to_length = len;
      return false;
    }
  }

  return true; // Unknown family
}

bool encode_macaddr(unsigned char *buffer, size_t buffer_size, const char *from, size_t from_len, size_t *length) {
  if (buffer_size < sizeof(MacAddr) || nullptr == buffer) {
    return true;
  }

  std::string from_str(from, from_len);
  MacAddr mac;

  if (!parse_mac_address(from_str.c_str(), mac.address, 6)) {
    return MarkInvalid(length); // Parse error
  }

  memcpy(buffer, &mac, sizeof(MacAddr));
  *length = sizeof(MacAddr);
  return false;
}

bool decode_macaddr(const unsigned char *buffer, size_t buffer_size, char *to, size_t to_size, size_t *to_length) {
  if (buffer_size < sizeof(MacAddr) || nullptr == buffer || nullptr == to) {
    return true;
  }

  MacAddr mac;
  memcpy(&mac, buffer, sizeof(MacAddr));

  char result[kMaxMacAddrString + 1];
  format_mac_address(mac.address, result, sizeof(result), 6);

  size_t len = strlen(result);
  if (len + 1 > to_size) return true;
  strcpy(to, result);
  *to_length = len;
  return false;
}

bool encode_macaddr8(unsigned char *buffer, size_t buffer_size, const char *from, size_t from_len, size_t *length) {
  if (buffer_size < sizeof(MacAddr8) || nullptr == buffer) {
    return true;
  }

  std::string from_str(from, from_len);
  MacAddr8 mac8;

  if (!parse_mac_address(from_str.c_str(), mac8.address, 8)) {
    return MarkInvalid(length); // Parse error
  }

  memcpy(buffer, &mac8, sizeof(MacAddr8));
  *length = sizeof(MacAddr8);
  return false;
}

bool decode_macaddr8(const unsigned char *buffer, size_t buffer_size, char *to, size_t to_size, size_t *to_length) {
  if (buffer_size < sizeof(MacAddr8) || nullptr == buffer || nullptr == to) {
    return true;
  }

  MacAddr8 mac8;
  memcpy(&mac8, buffer, sizeof(MacAddr8));

  char result[kMaxMacAddr8String + 1];
  format_mac_address(mac8.address, result, sizeof(result), 8);

  size_t len = strlen(result);
  if (len + 1 > to_size) return true;
  strcpy(to, result);
  *to_length = len;
  return false;
}

// Comparison functions for each type

int cmp_cidr(const unsigned char *data1, size_t len1, const unsigned char *data2, size_t len2) {
  // Both CIDR values should be the same size (IPv4Network or IPv6Network)
  if (len1 != len2) {
    // Different sizes mean different address families
    // IPv4 (7 bytes) sorts before IPv6 (19 bytes) per PostgreSQL spec
    return (len1 < len2) ? -1 : 1;
  }

  if (len1 == sizeof(IPv4Network)) {
    // Compare IPv4 networks
    IPv4Network net1, net2;
    memcpy(&net1, data1, sizeof(IPv4Network));
    memcpy(&net2, data2, sizeof(IPv4Network));

    // Compare network address first
    if (net1.address != net2.address) {
      return (net1.address < net2.address) ? -1 : 1;
    }

    // If network addresses are equal, compare netmask
    if (net1.netmask != net2.netmask) {
      return (net1.netmask < net2.netmask) ? -1 : 1;
    }

    return 0; // Equal
  } else if (len1 == sizeof(IPv6Network)) {
    // Compare IPv6 networks
    IPv6Network net1, net2;
    memcpy(&net1, data1, sizeof(IPv6Network));
    memcpy(&net2, data2, sizeof(IPv6Network));

    // Compare IPv6 addresses byte by byte
    int addr_cmp = memcmp(net1.address, net2.address, 16);
    if (addr_cmp != 0) {
      return (addr_cmp < 0) ? -1 : 1;
    }

    // If network addresses are equal, compare netmask
    if (net1.netmask != net2.netmask) {
      return (net1.netmask < net2.netmask) ? -1 : 1;
    }

    return 0; // Equal
  }

  // Fallback to binary comparison
  int result = memcmp(data1, data2, len1);
  if (result == 0) return 0;
  return (result < 0) ? -1 : 1;
}

int cmp_inet(const unsigned char *data1, size_t len1, const unsigned char *data2, size_t len2) {
  // INET comparison is the same as CIDR comparison
  // Both use the same internal structure and comparison logic
  return cmp_cidr(data1, len1, data2, len2);
}

int cmp_macaddr(const unsigned char *data1, size_t len1, const unsigned char *data2, size_t len2) {
  (void)len1;  // Used in assert, suppress warning
  (void)len2;  // Used in assert, suppress warning
  assert(sizeof(MacAddr) == len1);
  assert(len1 == len2);

  MacAddr mac1, mac2;
  memcpy(&mac1, data1, sizeof(MacAddr));
  memcpy(&mac2, data2, sizeof(MacAddr));

  // Binary comparison of MAC addresses
  int result = memcmp(mac1.address, mac2.address, 6);
  if (result == 0) return 0;
  return (result < 0) ? -1 : 1;
}

int cmp_macaddr8(const unsigned char *data1, size_t len1, const unsigned char *data2, size_t len2) {
  (void)len1;  // Used in assert, suppress warning
  (void)len2;  // Used in assert, suppress warning
  assert(sizeof(MacAddr8) == len1);
  assert(len1 == len2);

  MacAddr8 mac1, mac2;
  memcpy(&mac1, data1, sizeof(MacAddr8));
  memcpy(&mac2, data2, sizeof(MacAddr8));

  // Binary comparison of MAC addresses
  int result = memcmp(mac1.address, mac2.address, 8);
  if (result == 0) return 0;
  return (result < 0) ? -1 : 1;
}

// ============================================================================
// Helper functions for mask calculations
// ============================================================================

// Calculate IPv4 netmask from prefix length
uint32_t prefix_to_netmask_ipv4(uint8_t prefix_len) {
  if (prefix_len == 0) {
    return 0;
  }
  if (prefix_len >= 32) {
    return 0xFFFFFFFF;
  }
  return ~((1u << (32 - prefix_len)) - 1);
}

// Calculate IPv4 hostmask from prefix length (inverse of netmask)
uint32_t prefix_to_hostmask_ipv4(uint8_t prefix_len) {
  if (prefix_len >= 32) {
    return 0;
  }
  return (1u << (32 - prefix_len)) - 1;
}

// Calculate IPv6 netmask from prefix length
void prefix_to_netmask_ipv6(uint8_t prefix_len, uint8_t *netmask) {
  memset(netmask, 0, 16);

  int full_bytes = prefix_len / 8;
  int remaining_bits = prefix_len % 8;

  // Set full bytes to 0xFF
  for (int i = 0; i < full_bytes && i < 16; i++) {
    netmask[i] = 0xFF;
  }

  // Set partial byte if exists
  if (full_bytes < 16 && remaining_bits > 0) {
    netmask[full_bytes] = 0xFF << (8 - remaining_bits);
  }
}

// Calculate IPv6 hostmask from prefix length (inverse of netmask)
void prefix_to_hostmask_ipv6(uint8_t prefix_len, uint8_t *hostmask) {
  memset(hostmask, 0, 16);

  int full_bytes = prefix_len / 8;
  int remaining_bits = prefix_len % 8;

  // Set partial byte if exists
  if (full_bytes < 16 && remaining_bits > 0) {
    hostmask[full_bytes] = ~(0xFF << (8 - remaining_bits));
    full_bytes++;
  }

  // Set remaining bytes to 0xFF
  for (int i = full_bytes; i < 16; i++) {
    hostmask[i] = 0xFF;
  }
}

// ============================================================================
// Simple Extractors
// ============================================================================

// Helper to get family from buffer
static inline uint8_t get_address_family(const unsigned char *buffer,
                                         size_t buffer_size) {
  if (buffer == nullptr || buffer_size < sizeof(IPv4Network)) {
    return 0;
  }

  // Try IPv4 first (family at offset 5)
  uint8_t family = buffer[5];
  if (family == AF_INET_VAL) {
    return AF_INET_VAL;
  }

  // Try IPv6 (family at offset 17)
  if (buffer_size >= sizeof(IPv6Network)) {
    family = buffer[17];
    if (family == AF_INET6_VAL) {
      return AF_INET6_VAL;
    }
  }

  return 0; // Unknown
}

// family(inet) → int
// Extract family of address; 4 for IPv4, 6 for IPv6
int inet_family(const unsigned char *buffer, size_t buffer_size) {
  uint8_t family = get_address_family(buffer, buffer_size);

  if (family == AF_INET_VAL) {
    return 4;  // IPv4
  } else if (family == AF_INET6_VAL) {
    return 6;  // IPv6
  }

  return -1;  // Unknown family
}

// masklen(inet) → int
// Extract netmask length
int inet_masklen(const unsigned char *buffer, size_t buffer_size) {
  if (buffer == nullptr || buffer_size < sizeof(IPv4Network)) {
    return -1;  // Error
  }

  uint8_t family = get_address_family(buffer, buffer_size);

  if (family == AF_INET_VAL) {
    return buffer[4]; // Netmask at offset 4 for IPv4
  } else if (family == AF_INET6_VAL) {
    return buffer[16]; // Netmask at offset 16 for IPv6
  }

  return -1;  // Error
}

// host(inet) → text
// Extract IP address as text (without netmask)
bool inet_host(const unsigned char *buffer, size_t buffer_size, char *result, size_t result_size, size_t *result_length) {
  if (buffer == nullptr || buffer_size < sizeof(IPv4Network) || result == nullptr) {
    return true;  // Error
  }

  uint8_t family = get_address_family(buffer, buffer_size);

  if (family == AF_INET_VAL) {
    IPv4Network net;
    memcpy(&net, buffer, sizeof(IPv4Network));

    char addr_str[kMaxIPv4String];
    format_ipv4_address(net.address, addr_str, sizeof(addr_str));

    size_t len = strlen(addr_str);
    if (len + 1 > result_size) return true;
    strcpy(result, addr_str);
    *result_length = len;
    return false;  // Success

  } else if (family == AF_INET6_VAL && buffer_size >= sizeof(IPv6Network)) {
    IPv6Network net;
    memcpy(&net, buffer, sizeof(IPv6Network));

    char addr_str[kMaxIPv6String];
    format_ipv6_address(net.address, addr_str, sizeof(addr_str));

    size_t len = strlen(addr_str);
    if (len + 1 > result_size) return true;
    strcpy(result, addr_str);
    *result_length = len;
    return false;  // Success
  }

  return true;  // Error: unknown family
}

// text(inet) → text
// Extract IP address and netmask length as text (always include prefix)
bool inet_text(const unsigned char *buffer, size_t buffer_size, char *result, size_t result_size, size_t *result_length) {
  if (buffer == nullptr || buffer_size < sizeof(IPv4Network) || result == nullptr) {
    return true;  // Error
  }

  uint8_t family = get_address_family(buffer, buffer_size);

  if (family == AF_INET_VAL) {
    IPv4Network net;
    memcpy(&net, buffer, sizeof(IPv4Network));

    char addr_str[kMaxIPv4String];
    format_ipv4_address(net.address, addr_str, sizeof(addr_str));

    char result_str[kMaxIPv4String];
    snprintf(result_str, sizeof(result_str), "%s/%u", addr_str, net.netmask);

    size_t len = strlen(result_str);
    if (len + 1 > result_size) return true;
    strcpy(result, result_str);
    *result_length = len;
    return false;  // Success

  } else if (family == AF_INET6_VAL && buffer_size >= sizeof(IPv6Network)) {
    IPv6Network net;
    memcpy(&net, buffer, sizeof(IPv6Network));

    char addr_str[kMaxIPv6String];
    format_ipv6_address(net.address, addr_str, sizeof(addr_str));

    char result_str[kMaxIPv6String];
    snprintf(result_str, sizeof(result_str), "%s/%u", addr_str, net.netmask);

    size_t len = strlen(result_str);
    if (len + 1 > result_size) return true;
    strcpy(result, result_str);
    *result_length = len;
    return false;  // Success
  }

  return true;  // Error: unknown family
}

// ============================================================================
// Mask Calculations
// ============================================================================

// netmask(inet) → inet
// Construct netmask for network
bool inet_netmask(const unsigned char *buffer, size_t buffer_size,
                  unsigned char *result_buffer, size_t *result_length) {
  if (buffer == nullptr || buffer_size < sizeof(IPv4Network) ||
      result_buffer == nullptr || result_length == nullptr) {
    return true;  // Error
  }

  uint8_t family = get_address_family(buffer, buffer_size);

  if (family == AF_INET_VAL && buffer_size >= sizeof(IPv4Network)) {
    IPv4Network net;
    memcpy(&net, buffer, sizeof(IPv4Network));

    // Create netmask from prefix length
    uint32_t netmask_addr = prefix_to_netmask_ipv4(net.netmask);

    // Create result as INET with the netmask address and /32
    IPv4Network result;
    result.address = netmask_addr;
    result.netmask = 32;  // Netmask is always shown as /32
    result.family = AF_INET_VAL;
    result.flags = ADDR_FLAG_INET;

    memcpy(result_buffer, &result, sizeof(IPv4Network));
    *result_length = sizeof(IPv4Network);
    return false;  // Success

  } else if (family == AF_INET6_VAL && buffer_size >= sizeof(IPv6Network)) {
    IPv6Network net;
    memcpy(&net, buffer, sizeof(IPv6Network));

    // Create netmask from prefix length
    IPv6Network result;
    prefix_to_netmask_ipv6(net.netmask, result.address);
    result.netmask = 128; // Netmask is always shown as /128
    result.family = AF_INET6_VAL;
    result.flags = ADDR_FLAG_INET;

    memcpy(result_buffer, &result, sizeof(IPv6Network));
    *result_length = sizeof(IPv6Network);
    return false; // Success
  }

  return true;  // Error: unsupported family
}

// hostmask(inet) → inet
// Construct host mask for network (inverse of netmask)
bool inet_hostmask(const unsigned char *buffer, size_t buffer_size,
                   unsigned char *result_buffer, size_t *result_length) {
  if (buffer == nullptr || buffer_size < sizeof(IPv4Network) ||
      result_buffer == nullptr || result_length == nullptr) {
    return true;  // Error
  }

  uint8_t family = get_address_family(buffer, buffer_size);

  if (family == AF_INET_VAL && buffer_size >= sizeof(IPv4Network)) {
    IPv4Network net;
    memcpy(&net, buffer, sizeof(IPv4Network));

    // Create hostmask from prefix length
    uint32_t hostmask_addr = prefix_to_hostmask_ipv4(net.netmask);

    // Create result as INET with the hostmask address and /32
    IPv4Network result;
    result.address = hostmask_addr;
    result.netmask = 32;  // Hostmask is always shown as /32
    result.family = AF_INET_VAL;
    result.flags = ADDR_FLAG_INET;

    memcpy(result_buffer, &result, sizeof(IPv4Network));
    *result_length = sizeof(IPv4Network);
    return false;  // Success

  } else if (family == AF_INET6_VAL && buffer_size >= sizeof(IPv6Network)) {
    IPv6Network net;
    memcpy(&net, buffer, sizeof(IPv6Network));

    // Create hostmask from prefix length
    IPv6Network result;
    prefix_to_hostmask_ipv6(net.netmask, result.address);
    result.netmask = 128; // Hostmask is always shown as /128
    result.family = AF_INET6_VAL;
    result.flags = ADDR_FLAG_INET;

    memcpy(result_buffer, &result, sizeof(IPv6Network));
    *result_length = sizeof(IPv6Network);
    return false; // Success
  }

  return true;  // Error: unsupported family
}

// broadcast(inet) → inet
// Calculate broadcast address for network
bool inet_broadcast(const unsigned char *buffer, size_t buffer_size,
                    unsigned char *result_buffer, size_t *result_length) {
  if (buffer == nullptr || buffer_size < sizeof(IPv4Network) ||
      result_buffer == nullptr || result_length == nullptr) {
    return true;  // Error
  }

  uint8_t family = get_address_family(buffer, buffer_size);

  if (family == AF_INET_VAL && buffer_size >= sizeof(IPv4Network)) {
    IPv4Network net;
    memcpy(&net, buffer, sizeof(IPv4Network));

    // Calculate broadcast: address OR hostmask
    uint32_t hostmask = prefix_to_hostmask_ipv4(net.netmask);
    uint32_t broadcast_addr = net.address | hostmask;

    // Create result as INET with the broadcast address and same netmask
    IPv4Network result;
    result.address = broadcast_addr;
    result.netmask = net.netmask;
    result.family = AF_INET_VAL;
    result.flags = ADDR_FLAG_INET;

    memcpy(result_buffer, &result, sizeof(IPv4Network));
    *result_length = sizeof(IPv4Network);
    return false;  // Success

  } else if (family == AF_INET6_VAL && buffer_size >= sizeof(IPv6Network)) {
    IPv6Network net;
    memcpy(&net, buffer, sizeof(IPv6Network));

    // Calculate broadcast: address OR hostmask
    IPv6Network result;
    uint8_t hostmask[16];
    prefix_to_hostmask_ipv6(net.netmask, hostmask);

    for (int i = 0; i < 16; i++) {
      result.address[i] = net.address[i] | hostmask[i];
    }
    result.netmask = net.netmask;
    result.family = AF_INET6_VAL;
    result.flags = ADDR_FLAG_INET;

    memcpy(result_buffer, &result, sizeof(IPv6Network));
    *result_length = sizeof(IPv6Network);
    return false; // Success
  }

  return true;  // Error: unsupported family
}

// network(inet) → cidr
// Extract network part of address (zero out host bits)
bool inet_network(const unsigned char *buffer, size_t buffer_size,
                  unsigned char *result_buffer, size_t *result_length) {
  if (buffer == nullptr || buffer_size < sizeof(IPv4Network) ||
      result_buffer == nullptr || result_length == nullptr) {
    return true;  // Error
  }

  uint8_t family = get_address_family(buffer, buffer_size);

  if (family == AF_INET_VAL && buffer_size >= sizeof(IPv4Network)) {
    IPv4Network net;
    memcpy(&net, buffer, sizeof(IPv4Network));

    // Calculate network: address AND netmask
    uint32_t netmask = prefix_to_netmask_ipv4(net.netmask);
    uint32_t network_addr = net.address & netmask;

    // Create result as CIDR (strict network address)
    IPv4Network result;
    result.address = network_addr;
    result.netmask = net.netmask;
    result.family = AF_INET_VAL;
    result.flags = ADDR_FLAG_CIDR;

    memcpy(result_buffer, &result, sizeof(IPv4Network));
    *result_length = sizeof(IPv4Network);
    return false;  // Success

  } else if (family == AF_INET6_VAL && buffer_size >= sizeof(IPv6Network)) {
    IPv6Network net;
    memcpy(&net, buffer, sizeof(IPv6Network));

    // Calculate network: address AND netmask
    IPv6Network result;
    uint8_t netmask[16];
    prefix_to_netmask_ipv6(net.netmask, netmask);

    for (int i = 0; i < 16; i++) {
      result.address[i] = net.address[i] & netmask[i];
    }
    result.netmask = net.netmask;
    result.family = AF_INET6_VAL;
    result.flags = ADDR_FLAG_CIDR;

    memcpy(result_buffer, &result, sizeof(IPv6Network));
    *result_length = sizeof(IPv6Network);
    return false; // Success
  }

  return true;  // Error: unsupported family
}

// ============================================================================
// Modifiers
// ============================================================================

// set_masklen(inet, int) → inet
// Set netmask length for inet value (does not modify address bits)
bool inet_set_masklen(const unsigned char *buffer, size_t buffer_size,
                      int new_masklen, unsigned char *result_buffer, size_t *result_length) {
  if (buffer == nullptr || buffer_size < sizeof(IPv4Network) ||
      result_buffer == nullptr || result_length == nullptr) {
    return true;  // Error
  }

  uint8_t family = get_address_family(buffer, buffer_size);

  if (family == AF_INET_VAL && buffer_size >= sizeof(IPv4Network)) {
    // Validate new masklen for IPv4
    if (new_masklen < 0 || new_masklen > 32) {
      return true;  // Invalid masklen
    }

    IPv4Network net;
    memcpy(&net, buffer, sizeof(IPv4Network));

    // Create result with same address but new netmask
    IPv4Network result;
    result.address = net.address;
    result.netmask = new_masklen;
    result.family = AF_INET_VAL;
    result.flags = ADDR_FLAG_INET;

    memcpy(result_buffer, &result, sizeof(IPv4Network));
    *result_length = sizeof(IPv4Network);
    return false;  // Success

  } else if (family == AF_INET6_VAL && buffer_size >= sizeof(IPv6Network)) {
    // Validate new masklen for IPv6
    if (new_masklen < 0 || new_masklen > 128) {
      return true; // Invalid masklen
    }

    IPv6Network net;
    memcpy(&net, buffer, sizeof(IPv6Network));

    // Create result with same address but new netmask
    IPv6Network result;
    memcpy(result.address, net.address, 16);
    result.netmask = new_masklen;
    result.family = AF_INET6_VAL;
    result.flags = ADDR_FLAG_INET;

    memcpy(result_buffer, &result, sizeof(IPv6Network));
    *result_length = sizeof(IPv6Network);
    return false; // Success
  }

  return true;  // Error: unsupported family
}

// set_masklen(cidr, int) → cidr
// Set netmask length for cidr value (zeros out host bits)
bool cidr_set_masklen(const unsigned char *buffer, size_t buffer_size,
                      int new_masklen, unsigned char *result_buffer, size_t *result_length) {
  if (buffer == nullptr || buffer_size < sizeof(IPv4Network) ||
      result_buffer == nullptr || result_length == nullptr) {
    return true;  // Error
  }

  uint8_t family = get_address_family(buffer, buffer_size);

  if (family == AF_INET_VAL && buffer_size >= sizeof(IPv4Network)) {
    // Validate new masklen for IPv4
    if (new_masklen < 0 || new_masklen > 32) {
      return true;  // Invalid masklen
    }

    IPv4Network net;
    memcpy(&net, buffer, sizeof(IPv4Network));

    // Calculate network address by zeroing host bits
    uint32_t netmask = prefix_to_netmask_ipv4(new_masklen);
    uint32_t network_addr = net.address & netmask;

    // Create result with network address and new netmask
    IPv4Network result;
    result.address = network_addr;
    result.netmask = new_masklen;
    result.family = AF_INET_VAL;
    result.flags = ADDR_FLAG_CIDR;

    memcpy(result_buffer, &result, sizeof(IPv4Network));
    *result_length = sizeof(IPv4Network);
    return false;  // Success

  } else if (family == AF_INET6_VAL && buffer_size >= sizeof(IPv6Network)) {
    // Validate new masklen for IPv6
    if (new_masklen < 0 || new_masklen > 128) {
      return true; // Invalid masklen
    }

    IPv6Network net;
    memcpy(&net, buffer, sizeof(IPv6Network));

    // Calculate network address by zeroing host bits
    IPv6Network result;
    uint8_t netmask[16];
    prefix_to_netmask_ipv6(new_masklen, netmask);

    for (int i = 0; i < 16; i++) {
      result.address[i] = net.address[i] & netmask[i];
    }
    result.netmask = new_masklen;
    result.family = AF_INET6_VAL;
    result.flags = ADDR_FLAG_CIDR;

    memcpy(result_buffer, &result, sizeof(IPv6Network));
    *result_length = sizeof(IPv6Network);
    return false; // Success
  }

  return true;  // Error: unsupported family
}

// trunc(macaddr) → macaddr
// Set last 3 bytes to zero (keep manufacturer OUI)
bool macaddr_trunc(const unsigned char *buffer, size_t buffer_size,
                   unsigned char *result_buffer, size_t *result_length) {
  if (buffer == nullptr || buffer_size < sizeof(MacAddr) ||
      result_buffer == nullptr || result_length == nullptr) {
    return true;  // Error
  }

  MacAddr mac;
  memcpy(&mac, buffer, sizeof(MacAddr));

  // Keep first 3 bytes (OUI), zero last 3 bytes
  mac.address[3] = 0;
  mac.address[4] = 0;
  mac.address[5] = 0;

  memcpy(result_buffer, &mac, sizeof(MacAddr));
  *result_length = sizeof(MacAddr);
  return false;  // Success
}

// ============================================================================
// Formatting (Abbreviation)
// ============================================================================

// abbrev(inet) → text
// Abbreviated display format - omit /32 for IPv4 single hosts
bool inet_abbrev(const unsigned char *buffer, size_t buffer_size, char *result, size_t result_size, size_t *result_length) {
  if (buffer == nullptr || buffer_size < sizeof(IPv4Network) || result == nullptr) {
    return true;  // Error
  }

  uint8_t family = get_address_family(buffer, buffer_size);

  if (family == AF_INET_VAL && buffer_size >= sizeof(IPv4Network)) {
    IPv4Network net;
    memcpy(&net, buffer, sizeof(IPv4Network));

    char addr_str[kMaxIPv4String];
    format_ipv4_address(net.address, addr_str, sizeof(addr_str));

    // Omit /32 for single host addresses
    if (net.netmask == 32) {
      size_t len = strlen(addr_str);
      if (len + 1 > result_size) return true;
      strcpy(result, addr_str);
      *result_length = len;
    } else {
      char result_str[kMaxIPv4String];
      snprintf(result_str, sizeof(result_str), "%s/%u", addr_str, net.netmask);
      size_t len = strlen(result_str);
      if (len + 1 > result_size) return true;
      strcpy(result, result_str);
      *result_length = len;
    }
    return false;  // Success

  } else if (family == AF_INET6_VAL && buffer_size >= sizeof(IPv6Network)) {
    IPv6Network net;
    memcpy(&net, buffer, sizeof(IPv6Network));

    char addr_str[kMaxIPv6String];
    format_ipv6_address(net.address, addr_str, sizeof(addr_str));

    // Omit /128 for single host addresses
    if (net.netmask == 128) {
      size_t len = strlen(addr_str);
      if (len + 1 > result_size) return true;
      strcpy(result, addr_str);
      *result_length = len;
    } else {
      char result_str[kMaxIPv6String];
      snprintf(result_str, sizeof(result_str), "%s/%u", addr_str, net.netmask);
      size_t len = strlen(result_str);
      if (len + 1 > result_size) return true;
      strcpy(result, result_str);
      *result_length = len;
    }
    return false;  // Success
  }

  return true;  // Error: unknown family
}

// abbrev(cidr) → text
// Abbreviated display format - show minimal significant octets
bool cidr_abbrev(const unsigned char *buffer, size_t buffer_size, char *result, size_t result_size, size_t *result_length) {
  if (buffer == nullptr || buffer_size < sizeof(IPv4Network) || result == nullptr) {
    return true;  // Error
  }

  uint8_t family = get_address_family(buffer, buffer_size);

  if (family == AF_INET_VAL && buffer_size >= sizeof(IPv4Network)) {
    IPv4Network net;
    memcpy(&net, buffer, sizeof(IPv4Network));

    // Calculate how many octets we need to show based on netmask
    int significant_octets = (net.netmask + 7) / 8;  // Round up
    if (significant_octets == 0) significant_octets = 1;  // Show at least first octet

    // Extract octets
    uint8_t octets[4];
    octets[0] = (net.address >> 24) & 0xFF;
    octets[1] = (net.address >> 16) & 0xFF;
    octets[2] = (net.address >> 8) & 0xFF;
    octets[3] = net.address & 0xFF;

    // Build abbreviated address string
    char addr_str[kMaxIPv4String];
    if (significant_octets == 1) {
      snprintf(addr_str, sizeof(addr_str), "%u", octets[0]);
    } else if (significant_octets == 2) {
      snprintf(addr_str, sizeof(addr_str), "%u.%u", octets[0], octets[1]);
    } else if (significant_octets == 3) {
      snprintf(addr_str, sizeof(addr_str), "%u.%u.%u", octets[0], octets[1], octets[2]);
    } else {
      snprintf(addr_str, sizeof(addr_str), "%u.%u.%u.%u", octets[0], octets[1], octets[2], octets[3]);
    }

    char result_str[kMaxIPv4String];
    snprintf(result_str, sizeof(result_str), "%s/%u", addr_str, net.netmask);
    size_t len = strlen(result_str);
    if (len + 1 > result_size) return true;
    strcpy(result, result_str);
    *result_length = len;
    return false;  // Success

  } else if (family == AF_INET6_VAL && buffer_size >= sizeof(IPv6Network)) {
    // For IPv6, just use the same format as inet_text for now
    // A more sophisticated implementation would abbreviate groups
    IPv6Network net;
    memcpy(&net, buffer, sizeof(IPv6Network));

    char addr_str[kMaxIPv6String];
    format_ipv6_address(net.address, addr_str, sizeof(addr_str));

    char result_str[kMaxIPv6String];
    snprintf(result_str, sizeof(result_str), "%s/%u", addr_str, net.netmask);
    size_t len = strlen(result_str);
    if (len + 1 > result_size) return true;
    strcpy(result, result_str);
    *result_length = len;
    return false;  // Success
  }

  return true;  // Error: unknown family
}

} // namespace network_address

// =============================================================================
// VEF Registration
// =============================================================================

// Type name constants (array form required for make_type<> template parameter)
static constexpr const char kCidrTypeName[] = "CIDR";
static constexpr const char kInetTypeName[] = "INET";
static constexpr const char kMacaddrTypeName[] = "MACADDR";
static constexpr const char kMacaddr8TypeName[] = "MACADDR8";

// =============================================================================
// Typed encode/decode/compare wrappers for each type
// These thin wrappers call into the raw-buffer implementations above.
// They serve as both the type's encode/decode/compare functions and the
// user-callable cidr_from_string / cidr_to_string VDFs.
// =============================================================================

// --- CIDR ---
void encode_cidr(std::string_view from, CustomResult out) {
  auto buf = out.buffer();
  size_t length;
  if (network_address::encode_cidr(
          reinterpret_cast<unsigned char *>(buf.data()), buf.size(),
          from.data(), from.size(), &length)) {
    out.error("invalid CIDR address");
    return;
  }
  out.set_length(length);
}
void decode_cidr(CustomArg in, StringResult out) {
  if (in.is_null()) {
    out.set_null();
    return;
  }
  auto span = in.value();
  auto buf = out.buffer();
  size_t length;
  if (network_address::decode_cidr(
          reinterpret_cast<const unsigned char *>(span.data()), span.size(),
          buf.data(), buf.size(), &length)) {
    out.warning("CIDR decode error");
    return;
  }
  out.set_length(length);
}
int cmp_cidr(CustomArg a, CustomArg b) {
  auto sa = a.value(), sb = b.value();
  return network_address::cmp_cidr(
      reinterpret_cast<const unsigned char *>(sa.data()), sa.size(),
      reinterpret_cast<const unsigned char *>(sb.data()), sb.size());
}

// --- INET ---
void encode_inet(std::string_view from, CustomResult out) {
  auto buf = out.buffer();
  size_t length;
  if (network_address::encode_inet(
          reinterpret_cast<unsigned char *>(buf.data()), buf.size(),
          from.data(), from.size(), &length)) {
    out.error("invalid INET address");
    return;
  }
  out.set_length(length);
}
void decode_inet(CustomArg in, StringResult out) {
  if (in.is_null()) {
    out.set_null();
    return;
  }
  auto span = in.value();
  auto buf = out.buffer();
  size_t length;
  if (network_address::decode_inet(
          reinterpret_cast<const unsigned char *>(span.data()), span.size(),
          buf.data(), buf.size(), &length)) {
    out.warning("INET decode error");
    return;
  }
  out.set_length(length);
}
int cmp_inet(CustomArg a, CustomArg b) {
  auto sa = a.value(), sb = b.value();
  return network_address::cmp_inet(
      reinterpret_cast<const unsigned char *>(sa.data()), sa.size(),
      reinterpret_cast<const unsigned char *>(sb.data()), sb.size());
}

// --- MACADDR ---
void encode_macaddr(std::string_view from, CustomResult out) {
  auto buf = out.buffer();
  size_t length;
  if (network_address::encode_macaddr(
          reinterpret_cast<unsigned char *>(buf.data()), buf.size(),
          from.data(), from.size(), &length)) {
    out.error("invalid MAC address");
    return;
  }
  out.set_length(length);
}
void decode_macaddr(CustomArg in, StringResult out) {
  if (in.is_null()) {
    out.set_null();
    return;
  }
  auto span = in.value();
  auto buf = out.buffer();
  size_t length;
  if (network_address::decode_macaddr(
          reinterpret_cast<const unsigned char *>(span.data()), span.size(),
          buf.data(), buf.size(), &length)) {
    out.warning("MACADDR decode error");
    return;
  }
  out.set_length(length);
}
int cmp_macaddr(CustomArg a, CustomArg b) {
  auto sa = a.value(), sb = b.value();
  return network_address::cmp_macaddr(
      reinterpret_cast<const unsigned char *>(sa.data()), sa.size(),
      reinterpret_cast<const unsigned char *>(sb.data()), sb.size());
}

// --- MACADDR8 ---
void encode_macaddr8(std::string_view from, CustomResult out) {
  auto buf = out.buffer();
  size_t length;
  if (network_address::encode_macaddr8(
          reinterpret_cast<unsigned char *>(buf.data()), buf.size(),
          from.data(), from.size(), &length)) {
    out.error("invalid MAC address (EUI-64)");
    return;
  }
  out.set_length(length);
}
void decode_macaddr8(CustomArg in, StringResult out) {
  if (in.is_null()) {
    out.set_null();
    return;
  }
  auto span = in.value();
  auto buf = out.buffer();
  size_t length;
  if (network_address::decode_macaddr8(
          reinterpret_cast<const unsigned char *>(span.data()), span.size(),
          buf.data(), buf.size(), &length)) {
    out.warning("MACADDR8 decode error");
    return;
  }
  out.set_length(length);
}
int cmp_macaddr8(CustomArg a, CustomArg b) {
  auto sa = a.value(), sb = b.value();
  return network_address::cmp_macaddr8(
      reinterpret_cast<const unsigned char *>(sa.data()), sa.size(),
      reinterpret_cast<const unsigned char *>(sb.data()), sb.size());
}

// VDF wrappers for the from_string conversions: StringArg → CustomResult.
// These use .warning() (→ NULL) on invalid input, matching PostgreSQL behavior.
// The type-level encode_* functions use .error() (hard error) so that
// INSERT with invalid data fails rather than silently storing NULL.
// Helper: build "failed to parse string 'X'" message matching V1 format.
static std::string parse_error_msg(std::string_view input) {
  std::string msg = "failed to parse string '";
  msg.append(input.data(), input.size());
  msg += "'";
  return msg;
}

void cidr_from_string_vdf(StringArg s, CustomResult out) {
  if (s.is_null()) {
    out.set_null();
    return;
  }
  auto sv = s.value();
  auto buf = out.buffer();
  size_t length;
  if (network_address::encode_cidr(
          reinterpret_cast<unsigned char *>(buf.data()), buf.size(), sv.data(),
          sv.size(), &length)) {
    out.warning(parse_error_msg(sv));
    return;
  }
  out.set_length(length);
}
void inet_from_string_vdf(StringArg s, CustomResult out) {
  if (s.is_null()) {
    out.set_null();
    return;
  }
  auto sv = s.value();
  auto buf = out.buffer();
  size_t length;
  if (network_address::encode_inet(
          reinterpret_cast<unsigned char *>(buf.data()), buf.size(), sv.data(),
          sv.size(), &length)) {
    out.warning(parse_error_msg(sv));
    return;
  }
  out.set_length(length);
}
void macaddr_from_string_vdf(StringArg s, CustomResult out) {
  if (s.is_null()) {
    out.set_null();
    return;
  }
  auto sv = s.value();
  auto buf = out.buffer();
  size_t length;
  if (network_address::encode_macaddr(
          reinterpret_cast<unsigned char *>(buf.data()), buf.size(), sv.data(),
          sv.size(), &length)) {
    out.warning(parse_error_msg(sv));
    return;
  }
  out.set_length(length);
}
void macaddr8_from_string_vdf(StringArg s, CustomResult out) {
  if (s.is_null()) {
    out.set_null();
    return;
  }
  auto sv = s.value();
  auto buf = out.buffer();
  size_t length;
  if (network_address::encode_macaddr8(
          reinterpret_cast<unsigned char *>(buf.data()), buf.size(), sv.data(),
          sv.size(), &length)) {
    out.warning(parse_error_msg(sv));
    return;
  }
  out.set_length(length);
}

// =============================================================================
// VDF Wrapper Functions
// =============================================================================

// Helper: get raw const unsigned char* from CustomArg span
static inline const unsigned char *span_data(CustomArg arg) {
  return reinterpret_cast<const unsigned char *>(arg.value().data());
}
static inline size_t span_size(CustomArg arg) { return arg.value().size(); }

void cidr_compare_impl(CustomArg a, CustomArg b, IntResult out) {
  if (a.is_null() || b.is_null()) { out.set_null(); return; }
  out.set(cmp_cidr(a, b));
}
void inet_compare_impl(CustomArg a, CustomArg b, IntResult out) {
  if (a.is_null() || b.is_null()) { out.set_null(); return; }
  out.set(cmp_inet(a, b));
}
void macaddr_compare_impl(CustomArg a, CustomArg b, IntResult out) {
  if (a.is_null() || b.is_null()) { out.set_null(); return; }
  out.set(cmp_macaddr(a, b));
}
void macaddr8_compare_impl(CustomArg a, CustomArg b, IntResult out) {
  if (a.is_null() || b.is_null()) { out.set_null(); return; }
  out.set(cmp_macaddr8(a, b));
}

void inet_family_impl(CustomArg arg, IntResult out) {
  if (arg.is_null()) {
    out.set_null();
    return;
  }
  int family = network_address::inet_family(span_data(arg), span_size(arg));
  if (family < 0) {
    out.set_null();
    return;
  }
  out.set(family);
}
void inet_masklen_impl(CustomArg arg, IntResult out) {
  if (arg.is_null()) {
    out.set_null();
    return;
  }
  int masklen = network_address::inet_masklen(span_data(arg), span_size(arg));
  if (masklen < 0) {
    out.set_null();
    return;
  }
  out.set(masklen);
}
void inet_host_impl(CustomArg arg, StringResult out) {
  if (arg.is_null()) {
    out.set_null();
    return;
  }
  auto buf = out.buffer();
  size_t str_len;
  if (network_address::inet_host(span_data(arg), span_size(arg), buf.data(),
                                 buf.size(), &str_len)) {
    out.warning("inet_host: error");
    return;
  }
  out.set_length(str_len);
}
void inet_text_impl(CustomArg arg, StringResult out) {
  if (arg.is_null()) {
    out.set_null();
    return;
  }
  auto buf = out.buffer();
  size_t str_len;
  if (network_address::inet_text(span_data(arg), span_size(arg), buf.data(),
                                 buf.size(), &str_len)) {
    out.warning("inet_text: error");
    return;
  }
  out.set_length(str_len);
}
void inet_netmask_impl(CustomArg arg, CustomResult out) {
  if (arg.is_null()) {
    out.set_null();
    return;
  }
  auto buf = out.buffer();
  size_t bin_len;
  if (network_address::inet_netmask(
          span_data(arg), span_size(arg),
          reinterpret_cast<unsigned char *>(buf.data()), &bin_len)) {
    out.warning("inet_netmask: error");
    return;
  }
  out.set_length(bin_len);
}
void inet_hostmask_impl(CustomArg arg, CustomResult out) {
  if (arg.is_null()) {
    out.set_null();
    return;
  }
  auto buf = out.buffer();
  size_t bin_len;
  if (network_address::inet_hostmask(
          span_data(arg), span_size(arg),
          reinterpret_cast<unsigned char *>(buf.data()), &bin_len)) {
    out.warning("inet_hostmask: error");
    return;
  }
  out.set_length(bin_len);
}
void inet_broadcast_impl(CustomArg arg, CustomResult out) {
  if (arg.is_null()) {
    out.set_null();
    return;
  }
  auto buf = out.buffer();
  size_t bin_len;
  if (network_address::inet_broadcast(
          span_data(arg), span_size(arg),
          reinterpret_cast<unsigned char *>(buf.data()), &bin_len)) {
    out.warning("inet_broadcast: error");
    return;
  }
  out.set_length(bin_len);
}
void inet_network_impl(CustomArg arg, CustomResult out) {
  if (arg.is_null()) {
    out.set_null();
    return;
  }
  auto buf = out.buffer();
  size_t bin_len;
  if (network_address::inet_network(
          span_data(arg), span_size(arg),
          reinterpret_cast<unsigned char *>(buf.data()), &bin_len)) {
    out.warning("inet_network: error");
    return;
  }
  out.set_length(bin_len);
}
void inet_set_masklen_impl(CustomArg inet_arg, IntArg len_arg,
                           CustomResult out) {
  if (inet_arg.is_null() || len_arg.is_null()) {
    out.set_null();
    return;
  }
  auto buf = out.buffer();
  size_t bin_len;
  if (network_address::inet_set_masklen(
          span_data(inet_arg), span_size(inet_arg), (int)len_arg.value(),
          reinterpret_cast<unsigned char *>(buf.data()), &bin_len)) {
    out.warning("inet_set_masklen: error");
    return;
  }
  out.set_length(bin_len);
}
void cidr_set_masklen_impl(CustomArg cidr_arg, IntArg len_arg,
                           CustomResult out) {
  if (cidr_arg.is_null() || len_arg.is_null()) {
    out.set_null();
    return;
  }
  auto buf = out.buffer();
  size_t bin_len;
  if (network_address::cidr_set_masklen(
          span_data(cidr_arg), span_size(cidr_arg), (int)len_arg.value(),
          reinterpret_cast<unsigned char *>(buf.data()), &bin_len)) {
    out.warning("cidr_set_masklen: error");
    return;
  }
  out.set_length(bin_len);
}
void macaddr_trunc_impl(CustomArg arg, CustomResult out) {
  if (arg.is_null()) {
    out.set_null();
    return;
  }
  auto buf = out.buffer();
  size_t bin_len;
  if (network_address::macaddr_trunc(
          span_data(arg), span_size(arg),
          reinterpret_cast<unsigned char *>(buf.data()), &bin_len)) {
    out.warning("macaddr_trunc: error");
    return;
  }
  out.set_length(bin_len);
}
void inet_abbrev_impl(CustomArg arg, StringResult out) {
  if (arg.is_null()) {
    out.set_null();
    return;
  }
  auto buf = out.buffer();
  size_t str_len;
  if (network_address::inet_abbrev(span_data(arg), span_size(arg), buf.data(),
                                   buf.size(), &str_len)) {
    out.warning("inet_abbrev: error");
    return;
  }
  out.set_length(str_len);
}
void cidr_abbrev_impl(CustomArg arg, StringResult out) {
  if (arg.is_null()) {
    out.set_null();
    return;
  }
  auto buf = out.buffer();
  size_t str_len;
  if (network_address::cidr_abbrev(span_data(arg), span_size(arg), buf.data(),
                                   buf.size(), &str_len)) {
    out.warning("cidr_abbrev: error");
    return;
  }
  out.set_length(str_len);
}

// =============================================================================
// Type descriptors (constexpr — evaluated before VEF_GENERATE_ENTRY_POINTS)
// =============================================================================

constexpr auto CIDR = make_type<kCidrTypeName>()
                          .persisted_length(19)
                          .max_decode_buffer_length(64)
                          .from_string<&encode_cidr>()
                          .to_string<&decode_cidr>()
                          .compare<&cmp_cidr>()
                          .intrinsic_default_str("::/0")
                          .build();

constexpr auto INET = make_type<kInetTypeName>()
                          .persisted_length(19)
                          .max_decode_buffer_length(64)
                          .from_string<&encode_inet>()
                          .to_string<&decode_inet>()
                          .compare<&cmp_inet>()
                          .intrinsic_default_str("::")
                          .build();

constexpr auto MACADDR = make_type<kMacaddrTypeName>()
                             .persisted_length(6)
                             .max_decode_buffer_length(32)
                             .from_string<&encode_macaddr>()
                             .to_string<&decode_macaddr>()
                             .compare<&cmp_macaddr>()
                             .intrinsic_default_str("00:00:00:00:00:00")
                             .build();

constexpr auto MACADDR8 = make_type<kMacaddr8TypeName>()
                              .persisted_length(8)
                              .max_decode_buffer_length(32)
                              .from_string<&encode_macaddr8>()
                              .to_string<&decode_macaddr8>()
                              .compare<&cmp_macaddr8>()
                              .intrinsic_default_str("00:00:00:00:00:00:00:00")
                              .build();

VEF_GENERATE_ENTRY_POINTS(
    make_extension()
        .type(CIDR)
        .type(INET)
        .type(MACADDR)
        .type(MACADDR8)

        // Explicit conversion VDFs
        .func(make_func<&cidr_from_string_vdf>("cidr_from_string")
                  .returns(CIDR)
                  .param(STRING)
                  .buffer_size(19)
                  .build())
        .func(make_func<&decode_cidr>("cidr_to_string")
                  .returns(STRING)
                  .param(CIDR)
                  .buffer_size(64)
                  .build())
        .func(make_func<&inet_from_string_vdf>("inet_from_string")
                  .returns(INET)
                  .param(STRING)
                  .buffer_size(19)
                  .build())
        .func(make_func<&decode_inet>("inet_to_string")
                  .returns(STRING)
                  .param(INET)
                  .buffer_size(64)
                  .build())
        .func(make_func<&macaddr_from_string_vdf>("macaddr_from_string")
                  .returns(MACADDR)
                  .param(STRING)
                  .buffer_size(6)
                  .build())
        .func(make_func<&decode_macaddr>("macaddr_to_string")
                  .returns(STRING)
                  .param(MACADDR)
                  .buffer_size(32)
                  .build())
        .func(make_func<&macaddr8_from_string_vdf>("macaddr8_from_string")
                  .returns(MACADDR8)
                  .param(STRING)
                  .buffer_size(8)
                  .build())
        .func(make_func<&decode_macaddr8>("macaddr8_to_string")
                  .returns(STRING)
                  .param(MACADDR8)
                  .buffer_size(32)
                  .build())

        // Comparison
        .func(make_func<&cidr_compare_impl>("cidr_compare")
                  .returns(INT)
                  .param(CIDR)
                  .param(CIDR)
                  .build())
        .func(make_func<&inet_compare_impl>("inet_compare")
                  .returns(INT)
                  .param(INET)
                  .param(INET)
                  .build())
        .func(make_func<&macaddr_compare_impl>("macaddr_compare")
                  .returns(INT)
                  .param(MACADDR)
                  .param(MACADDR)
                  .build())
        .func(make_func<&macaddr8_compare_impl>("macaddr8_compare")
                  .returns(INT)
                  .param(MACADDR8)
                  .param(MACADDR8)
                  .build())

        // Simple extractors
        .func(make_func<&inet_family_impl>("inet_family")
                  .returns(INT)
                  .param(INET)
                  .build())
        .func(make_func<&inet_masklen_impl>("inet_masklen")
                  .returns(INT)
                  .param(INET)
                  .build())
        .func(make_func<&inet_host_impl>("inet_host")
                  .returns(STRING)
                  .param(INET)
                  .buffer_size(64)
                  .build())
        .func(make_func<&inet_text_impl>("inet_text")
                  .returns(STRING)
                  .param(INET)
                  .buffer_size(64)
                  .build())

        // Mask calculations
        .func(make_func<&inet_netmask_impl>("inet_netmask")
                  .returns(INET)
                  .param(INET)
                  .buffer_size(19)
                  .build())
        .func(make_func<&inet_hostmask_impl>("inet_hostmask")
                  .returns(INET)
                  .param(INET)
                  .buffer_size(19)
                  .build())
        .func(make_func<&inet_broadcast_impl>("inet_broadcast")
                  .returns(INET)
                  .param(INET)
                  .buffer_size(19)
                  .build())
        .func(make_func<&inet_network_impl>("inet_network")
                  .returns(CIDR)
                  .param(INET)
                  .buffer_size(19)
                  .build())

        // Modifiers
        .func(make_func<&inet_set_masklen_impl>("inet_set_masklen")
                  .returns(INET)
                  .param(INET)
                  .param(INT)
                  .buffer_size(19)
                  .build())
        .func(make_func<&cidr_set_masklen_impl>("cidr_set_masklen")
                  .returns(CIDR)
                  .param(CIDR)
                  .param(INT)
                  .buffer_size(19)
                  .build())
        .func(make_func<&macaddr_trunc_impl>("macaddr_trunc")
                  .returns(MACADDR)
                  .param(MACADDR)
                  .buffer_size(6)
                  .build())

        // Formatting
        .func(make_func<&inet_abbrev_impl>("inet_abbrev")
                  .returns(STRING)
                  .param(INET)
                  .buffer_size(64)
                  .build())
        .func(make_func<&cidr_abbrev_impl>("cidr_abbrev")
                  .returns(STRING)
                  .param(CIDR)
                  .buffer_size(64)
                  .build()))

cmake_minimum_required(VERSION 3.16)
project(vsql_network_address_extension)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Extension name
set(EXTENSION_NAME "vsql_network_address")

# Find VillageSQL SDK
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(VillageSQL REQUIRED)

message(STATUS "VillageSQL SDK found at: ${VillageSQL_PREFIX}")
message(STATUS "VillageSQL include dir: ${VillageSQL_INCLUDE_DIR}")

# Find OpenSSL (required for network address functions)
find_package(OpenSSL REQUIRED)
message(STATUS "OpenSSL include: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")

# Create the Network Address shared library
add_library(network_address SHARED
    src/network_address.cc
)

# Include directories
target_include_directories(network_address PRIVATE
    ${VillageSQLExtensionFramework_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

# Link OpenSSL
target_link_libraries(network_address PRIVATE ${OPENSSL_LIBRARIES})

# Create the VEB package
VEF_CREATE_VEB(
    NAME ${EXTENSION_NAME}
    LIBRARY_TARGET network_address
    MANIFEST ${CMAKE_CURRENT_SOURCE_DIR}/manifest.json
)

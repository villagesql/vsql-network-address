-- Network Address Extension Installation Script
-- Provides INET, CIDR, MACADDR, and MACADDR8 types for VillageSQL

USE villagesql;

-- CIDR functions
CREATE FUNCTION IF NOT EXISTS cidr_to_string RETURNS STRING SONAME "network_address.so";
CREATE FUNCTION IF NOT EXISTS cidr_from_string RETURNS STRING SONAME "network_address.so";
CREATE FUNCTION IF NOT EXISTS cidr_compare RETURNS INTEGER SONAME "network_address.so";

-- INET functions
CREATE FUNCTION IF NOT EXISTS inet_to_string RETURNS STRING SONAME "network_address.so";
CREATE FUNCTION IF NOT EXISTS inet_from_string RETURNS STRING SONAME "network_address.so";
CREATE FUNCTION IF NOT EXISTS inet_compare RETURNS INTEGER SONAME "network_address.so";

-- MACADDR functions
CREATE FUNCTION IF NOT EXISTS macaddr_to_string RETURNS STRING SONAME "network_address.so";
CREATE FUNCTION IF NOT EXISTS macaddr_from_string RETURNS STRING SONAME "network_address.so";
CREATE FUNCTION IF NOT EXISTS macaddr_compare RETURNS INTEGER SONAME "network_address.so";

-- MACADDR8 functions
CREATE FUNCTION IF NOT EXISTS macaddr8_to_string RETURNS STRING SONAME "network_address.so";
CREATE FUNCTION IF NOT EXISTS macaddr8_from_string RETURNS STRING SONAME "network_address.so";
CREATE FUNCTION IF NOT EXISTS macaddr8_compare RETURNS INTEGER SONAME "network_address.so";

-- Simple Extractors
CREATE FUNCTION IF NOT EXISTS inet_family RETURNS INTEGER SONAME "network_address.so";
CREATE FUNCTION IF NOT EXISTS inet_masklen RETURNS INTEGER SONAME "network_address.so";
CREATE FUNCTION IF NOT EXISTS inet_host RETURNS STRING SONAME "network_address.so";
CREATE FUNCTION IF NOT EXISTS inet_text RETURNS STRING SONAME "network_address.so";

-- Mask Calculations
CREATE FUNCTION IF NOT EXISTS inet_netmask RETURNS STRING SONAME "network_address.so";
CREATE FUNCTION IF NOT EXISTS inet_hostmask RETURNS STRING SONAME "network_address.so";
CREATE FUNCTION IF NOT EXISTS inet_broadcast RETURNS STRING SONAME "network_address.so";
CREATE FUNCTION IF NOT EXISTS inet_network RETURNS STRING SONAME "network_address.so";

-- Modifiers
CREATE FUNCTION IF NOT EXISTS inet_set_masklen RETURNS STRING SONAME "network_address.so";
CREATE FUNCTION IF NOT EXISTS cidr_set_masklen RETURNS STRING SONAME "network_address.so";
CREATE FUNCTION IF NOT EXISTS macaddr_trunc RETURNS STRING SONAME "network_address.so";

-- Formatting (Abbreviation)
CREATE FUNCTION IF NOT EXISTS inet_abbrev RETURNS STRING SONAME "network_address.so";
CREATE FUNCTION IF NOT EXISTS cidr_abbrev RETURNS STRING SONAME "network_address.so";

-- Create types
CREATE TYPE CIDR AS "{\"length\": 20, \"to_string\": \"cidr_to_string\", \"from_string\": \"cidr_from_string\", \"compare\": \"cidr_compare\"}";
CREATE TYPE INET AS "{\"length\": 20, \"to_string\": \"inet_to_string\", \"from_string\": \"inet_from_string\", \"compare\": \"inet_compare\"}";
CREATE TYPE MACADDR AS "{\"length\": 7, \"to_string\": \"macaddr_to_string\", \"from_string\": \"macaddr_from_string\", \"compare\": \"macaddr_compare\"}";
CREATE TYPE MACADDR8 AS "{\"length\": 9, \"to_string\": \"macaddr8_to_string\", \"from_string\": \"macaddr8_from_string\", \"compare\": \"macaddr8_compare\"}";
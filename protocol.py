"""
Protocol module for SOCKSv5 proxy server.

This module contains all SOCKS5 protocol-related constants and utility functions
as defined in RFC 1928. It provides the protocol codes for version, commands,
address types, reply codes, and authentication methods.
"""


# ==================== SOCKS Protocol Versions ====================
# SOCKS version 5 (current standard as per RFC 1928)
SOCKS_VERSION = 0x05


# ==================== Authentication Methods ====================
# Method 0x00: No authentication required
NO_AUTH = 0x00

# Method 0xFF: No acceptable methods (client and server have no common auth method)
NO_ACCEPTABLE_METHODS = 0xFF

# Note: Other methods like 0x02 (Username/Password), 0x03 (GSSAPI) are not implemented


# ==================== SOCKS Commands ====================
# Command 0x01: CONNECT - Establish a TCP/IP stream connection to destination
CMD_CONNECT = 0x01

# Command 0x02: BIND - Request server to listen for incoming TCP connections
# (Not implemented in this server)
CMD_BIND = 0x02

# Command 0x03: UDP ASSOCIATE - Establish a UDP relay association
# (Not implemented in this server)
CMD_UDP_ASSOCIATE = 0x03


# ==================== Address Types (ATYP) ====================
# Type 0x01: IPv4 address (4 bytes)
ATYP_IPV4 = 0x01

# Type 0x03: Domain name (first byte is length, followed by domain name)
ATYP_DOMAIN = 0x03

# Type 0x04: IPv6 address (16 bytes)
ATYP_IPV6 = 0x04


# ==================== Reply Codes (REP) ====================
# Reply 0x00: Succeeded
REP_SUCCESS = 0x00

# Reply 0x01: General SOCKS server failure
REP_GENERAL_FAILURE = 0x01

# Reply 0x02: Connection not allowed by ruleset
REP_CONNECTION_NOT_ALLOWED = 0x02

# Reply 0x03: Network unreachable
REP_NETWORK_UNREACHABLE = 0x03

# Reply 0x04: Host unreachable
REP_HOST_UNREACHABLE = 0x04

# Reply 0x05: Connection refused
REP_CONNECTION_REFUSED = 0x05

# Reply 0x06: TTL expired
REP_TTL_EXPIRED = 0x06

# Reply 0x07: Command not supported
REP_COMMAND_NOT_SUPPORTED = 0x07

# Reply 0x08: Address type not supported
REP_ADDRESS_TYPE_NOT_SUPPORTED = 0x08


# ==================== Protocol Constants ====================
# Reserved byte in SOCKS protocol (always 0x00)
RESERVED = 0x00

# Minimum handshake length: VER(1) + NMETHODS(1) + at least one method(1)
MIN_HANDSHAKE_LENGTH = 3

# Minimum request length: VER(1) + CMD(1) + RSV(1) + ATYP(1) + ADDR(min 4) + PORT(2)
MIN_REQUEST_LENGTH = 4

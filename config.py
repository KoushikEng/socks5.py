"""
Configuration module for SOCKSv5 proxy server.

This module contains all configurable parameters for the server, including
network settings, buffer sizes, timeouts, and logging configuration.
"""

import logging

# ==================== Server Configuration ====================
# Default host address to bind to (0.0.0.0 accepts connections from any interface)
DEFAULT_HOST = '0.0.0.0'

# Default port to listen on (standard SOCKS proxy port)
DEFAULT_PORT = 1080

# Maximum number of pending connections in the socket queue
BACKLOG = 5


# ==================== Buffer and Size Configuration ====================
# Maximum buffer size for receiving handshake data (262 bytes per RFC 1928)
HANDSHAKE_BUFFER_SIZE = 262

# Buffer size for data relay operations (4KB)
DATA_BUFFER_SIZE = 4096


# ==================== Timeout Configuration ====================
# Select timeout in seconds for data relay operations
# If no data is received within this time, the connection is closed
SELECT_TIMEOUT = 30


# ==================== Logging Configuration ====================
# Logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_LEVEL = logging.INFO

# Logging format: timestamp - level - message
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'


# ==================== Socket Configuration ====================
# Enable socket address reuse (allows binding to same port quickly after restart)
SOCKET_REUSE_ADDR = True


# ==================== Threading Configuration ====================
# Whether client handler threads should be daemon threads
# Daemon threads are terminated when the main program exits
THREAD_DAEMON = True

"""
Handlers module for SOCKSv5 proxy server.

This module contains functions for handling the SOCKS5 protocol including
handshake negotiation, request parsing, and connection establishment.
"""

import socket
import struct
import logging

from config import HANDSHAKE_BUFFER_SIZE
from protocol import (
    SOCKS_VERSION, NO_AUTH, NO_ACCEPTABLE_METHODS,
    CMD_CONNECT, ATYP_IPV4, ATYP_DOMAIN, ATYP_IPV6,
    REP_SUCCESS, REP_GENERAL_FAILURE, REP_HOST_UNREACHABLE,
    REP_CONNECTION_REFUSED, REP_COMMAND_NOT_SUPPORTED,
    REP_ADDRESS_TYPE_NOT_SUPPORTED, RESERVED
)

logger = logging.getLogger(__name__)


def perform_handshake(client_socket):
    """
    Performs SOCKS5 handshake with the client.

    The SOCKS5 handshake consists of two steps:
    1. Client sends a greeting with supported authentication methods
    2. Server selects a method and responds

    This server currently supports only NO_AUTH (method 0x00).

    Args:
        client_socket: Socket connected to the SOCKS client

    Returns:
        bool: True if handshake succeeded, False otherwise

    Process:
        1. Read client greeting (VER + NMETHODS + METHODS)
        2. Validate SOCKS version (must be 0x05)
        3. Check if NO_AUTH method is supported
        4. Send response with selected method or NO_ACCEPTABLE_METHODS
    """
    try:
        # Read client greeting message
        # Maximum size is 262 bytes per RFC 1928
        data = client_socket.recv(HANDSHAKE_BUFFER_SIZE)

        # Validate minimum handshake length
        if len(data) < 3:
            logger.warning('Handshake too short')
            return False

        # Parse version and number of methods
        version, nmethods = struct.unpack('!BB', data[:2])

        # Validate SOCKS version
        if version != SOCKS_VERSION:
            logger.warning(f'Invalid SOCKS version: {version}')
            return False

        # Extract list of authentication methods supported by client
        methods = list(data[2:2 + nmethods])

        # Check if NO_AUTH is in the supported methods
        if NO_AUTH in methods:
            # Send response: select NO_AUTH method
            client_socket.sendall(struct.pack('!BB', SOCKS_VERSION, NO_AUTH))
            logger.debug('Handshake completed with NO_AUTH')
            return True
        else:
            # Send response: no acceptable method
            client_socket.sendall(struct.pack('!BB', SOCKS_VERSION, NO_ACCEPTABLE_METHODS))
            logger.warning('No acceptable authentication method')
            return False

    except Exception as e:
        logger.error(f'Handshake error: {e}')
        return False


def parse_request(client_socket):
    """
    Parses a SOCKS5 connection request from the client.

    The request format is:
    VER(1) + CMD(1) + RSV(1) + ATYP(1) + DST.ADDR(variable) + DST.PORT(2)

    Args:
        client_socket: Socket connected to the SOCKS client

    Returns:
        tuple: (cmd, atyp, dst_addr, dst_port)
            - cmd: Command code (CONNECT, BIND, UDP_ASSOCIATE)
            - atyp: Address type (IPv4, Domain, IPv6)
            - dst_addr: Destination address (string)
            - dst_port: Destination port (integer)

    Raises:
        Exception: If request is malformed or address type is unsupported
    """
    # Read request from client
    data = client_socket.recv(HANDSHAKE_BUFFER_SIZE)

    # Validate minimum request length
    if len(data) < 4:
        raise Exception('Request too short')

    # Parse fixed header fields
    version, cmd, rsv, atyp = struct.unpack('!BBBB', data[:4])

    # Validate SOCKS version
    if version != SOCKS_VERSION:
        raise Exception(f'Invalid SOCKS version: {version}')

    # Parse destination address based on address type
    if atyp == ATYP_IPV4:
        # IPv4: 4 bytes for address + 2 bytes for port
        if len(data) < 10:
            raise Exception('Incomplete IPv4 request')
        dst_addr = socket.inet_ntoa(data[4:8])
        dst_port = struct.unpack('!H', data[8:10])[0]

    elif atyp == ATYP_DOMAIN:
        # Domain: 1 byte length + N bytes domain + 2 bytes port
        addr_len = data[4]
        if len(data) < 5 + addr_len + 2:
            raise Exception('Incomplete domain request')
        dst_addr = data[5:5 + addr_len].decode('utf-8')
        dst_port = struct.unpack('!H', data[5 + addr_len:7 + addr_len])[0]

    elif atyp == ATYP_IPV6:
        # IPv6: 16 bytes for address + 2 bytes for port
        if len(data) < 22:
            raise Exception('Incomplete IPv6 request')
        dst_addr = socket.inet_ntop(socket.AF_INET6, data[4:20])
        dst_port = struct.unpack('!H', data[20:22])[0]

    else:
        # Send error reply for unsupported address type
        send_reply(client_socket, REP_ADDRESS_TYPE_NOT_SUPPORTED)
        raise Exception(f'Unsupported address type: {atyp}')

    logger.debug(f'Parsed request: CMD={cmd}, ADDR={dst_addr}, PORT={dst_port}')
    return cmd, atyp, dst_addr, dst_port


def send_reply(client_socket, rep_code):
    """
    Sends a SOCKS5 reply to the client.

    The reply format is:
    VER(1) + REP(1) + RSV(1) + ATYP(1) + BND.ADDR(variable) + BND.PORT(2)

    For error replies, the bound address is set to 0.0.0.0:0

    Args:
        client_socket: Socket connected to the SOCKS client
        rep_code: Reply code indicating success or failure

    Note:
        This function silently ignores send errors as the connection may
        already be closed when sending error replies.
    """
    try:
        # Build reply with IPv4 bound address (even for errors)
        reply = struct.pack('!BBBB', SOCKS_VERSION, rep_code, RESERVED, ATYP_IPV4)
        reply += socket.inet_aton('0.0.0.0') + struct.pack('!H', 0)
        client_socket.sendall(reply)
    except Exception:
        # Ignore send errors - connection may already be closed
        pass


def handle_connect(client_socket, atyp, dst_addr, dst_port):
    """
    Handles CONNECT command by establishing connection to destination.

    Process:
        1. Create TCP socket and connect to destination
        2. Set sockets to non-blocking mode
        3. Send success reply to client
        4. Start bidirectional data relay

    Args:
        client_socket: Socket connected to the SOCKS client
        atyp: Address type of destination
        dst_addr: Destination address
        dst_port: Destination port

    Error Handling:
        - DNS resolution failures -> REP_HOST_UNREACHABLE
        - Connection refused -> REP_CONNECTION_REFUSED
        - Other errors -> REP_GENERAL_FAILURE
    """
    try:
        # Log connection attempt
        logger.info(f'CONNECT to {dst_addr}:{dst_port}')

        # Create TCP socket and connect to destination
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.connect((dst_addr, dst_port))

        # Set both sockets to non-blocking mode for efficient relay
        remote_socket.setblocking(False)
        client_socket.setblocking(False)

        # Get the local address and port used for the connection
        # This is sent back to the client in the reply
        bind_addr = '0.0.0.0'
        bind_port = remote_socket.getsockname()[1]
        bind_ip = socket.inet_aton(bind_addr)

        # Send success reply to client with bound address
        reply = struct.pack('!BBBB', SOCKS_VERSION, REP_SUCCESS, RESERVED, ATYP_IPV4)
        reply += bind_ip + struct.pack('!H', bind_port)
        client_socket.sendall(reply)

        logger.info(f'Connected to {dst_addr}:{dst_port}')

        # Import here to avoid circular dependency
        from relay import relay_data

        # Start bidirectional data relay between client and remote
        relay_data(client_socket, remote_socket)

    except socket.gaierror:
        # DNS resolution failed
        logger.error(f'DNS resolution failed for {dst_addr}')
        send_reply(client_socket, REP_HOST_UNREACHABLE)
        client_socket.close()

    except ConnectionRefusedError:
        # Destination refused connection
        logger.error(f'Connection refused by {dst_addr}:{dst_port}')
        send_reply(client_socket, REP_CONNECTION_REFUSED)
        client_socket.close()

    except Exception as e:
        # General connection error
        logger.error(f'Connection error to {dst_addr}:{dst_port}: {e}')
        send_reply(client_socket, REP_GENERAL_FAILURE)
        client_socket.close()

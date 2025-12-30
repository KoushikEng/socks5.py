"""
Relay module for SOCKSv5 proxy server.

This module handles bidirectional data relay between the client socket and
the remote destination socket using non-blocking I/O and select().
"""

import select
import logging

from config import DATA_BUFFER_SIZE, SELECT_TIMEOUT

logger = logging.getLogger(__name__)


def relay_data(client_socket, remote_socket):
    """
    Relays data bidirectionally between client and remote sockets.

    This function uses select() to monitor both sockets for readable data.
    When data arrives on one socket, it is immediately forwarded to the other.
    Both sockets are set to non-blocking mode for efficient I/O.

    Args:
        client_socket: The socket connected to the SOCKS client
        remote_socket: The socket connected to the remote destination

    Process:
        1. Monitor both sockets using select() with timeout
        2. When data is available on a socket, read it and forward to the other
        3. Continue until either connection closes or timeout occurs
        4. Clean up and close both sockets

    Note:
        - Uses non-blocking I/O for efficient data transfer
        - Returns when either socket is closed or timeout occurs
        - Automatically handles BlockingIOError for non-blocking sockets
        - Both sockets are closed before function exits
    """
    try:
        # Main relay loop: continuously monitor both sockets for data
        while True:
            # Use select() to wait for data on either socket
            # This is more efficient than polling and allows handling multiple connections
            sockets = [client_socket, remote_socket]
            readable, _, _ = select.select(sockets, [], [], SELECT_TIMEOUT)

            # If no data received within timeout period, close connections
            if not readable:
                logger.debug('Relay timeout - closing connection')
                break

            # Process all sockets that have data available
            for sock in readable:
                try:
                    # Read data from the socket (non-blocking)
                    data = sock.recv(DATA_BUFFER_SIZE)

                    # If no data returned, the connection is closed
                    if not data:
                        logger.debug(f'Connection closed by {"client" if sock is client_socket else "remote"}')
                        return

                    # Forward data to the other socket
                    if sock is client_socket:
                        # Data from client -> send to remote
                        remote_socket.sendall(data)
                    else:
                        # Data from remote -> send to client
                        client_socket.sendall(data)

                except BlockingIOError:
                    # No data available on non-blocking socket, continue to next iteration
                    continue
                except Exception as e:
                    # Socket error occurred, terminate relay
                    logger.debug(f'Socket error during relay: {e}')
                    return

    except Exception as e:
        # Catch any unexpected errors during relay
        logger.debug(f'Relay error: {e}')
    finally:
        # Ensure both sockets are closed before exiting
        # This prevents resource leaks even if an error occurs
        try:
            remote_socket.close()
        except Exception:
            pass
        try:
            client_socket.close()
        except Exception:
            pass

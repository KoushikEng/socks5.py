"""
Server module for SOCKSv5 proxy server.

This module contains the main Socks5Server class that manages the server socket,
accepts incoming connections, and spawns handler threads for each client.
"""

import socket
import threading
import logging

from config import DEFAULT_HOST, DEFAULT_PORT, BACKLOG, SOCKET_REUSE_ADDR, THREAD_DAEMON
from protocol import CMD_CONNECT, REP_COMMAND_NOT_SUPPORTED

logger = logging.getLogger(__name__)


class Socks5Server:
    """
    Main SOCKSv5 proxy server class.

    This class is responsible for:
    - Creating and configuring the server socket
    - Listening for incoming client connections
    - Spawning handler threads for each client
    - Graceful shutdown on keyboard interrupt

    Attributes:
        host (str): Host address to bind to
        port (int): Port number to listen on
        server_socket (socket.socket): Server socket object
    """

    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT):
        """
        Initialize the SOCKSv5 server.

        Args:
            host (str): Host address to bind to (default: 0.0.0.0)
            port (int): Port number to listen on (default: 1080)
        """
        self.host = host
        self.port = port
        self.server_socket = None
        logger.debug(f'Server initialized: {host}:{port}')

    def start(self):
        """
        Start the SOCKSv5 server.

        This method:
        1. Creates a TCP socket
        2. Configures socket options (reuse address)
        3. Binds to the specified host and port
        4. Starts listening for connections
        5. Accepts connections in a loop, spawning handler threads

        The server runs until interrupted with Ctrl+C (KeyboardInterrupt).

        Note:
            - Each client connection is handled in a separate thread
            - Handler threads are daemon threads that terminate when main exits
            - Socket is properly closed in finally block even on error
        """
        # Create TCP socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Enable address reuse to allow quick restart
        # Without this, the port may be in TIME_WAIT state after shutdown
        if SOCKET_REUSE_ADDR:
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Bind to host and port
        self.server_socket.bind((self.host, self.port))

        # Start listening for incoming connections
        # backlog parameter specifies maximum queued connections
        self.server_socket.listen(BACKLOG)

        logger.info(f'SOCKS5 server listening on {self.host}:{self.port}')

        try:
            # Main server loop: accept connections continuously
            while True:
                # Accept incoming connection
                # This blocks until a client connects
                client_socket, client_address = self.server_socket.accept()

                # Log new connection
                logger.info(f'New connection from {client_address[0]}:{client_address[1]}')

                # Create a new thread to handle this client
                # Each thread handles one client connection independently
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address)
                )

                # Set as daemon thread so it doesn't prevent program exit
                client_thread.daemon = THREAD_DAEMON

                # Start the handler thread
                client_thread.start()

        except KeyboardInterrupt:
            # User interrupted with Ctrl+C
            logger.info('Server shutting down...')
        finally:
            # Ensure server socket is closed
            self.server_socket.close()
            logger.info('Server stopped')

    def handle_client(self, client_socket, client_address):
        """
        Handle a single client connection.

        This method runs in a separate thread for each client and:
        1. Performs SOCKS5 handshake
        2. Parses the client request
        3. Handles CONNECT commands
        4. Closes the connection on error or completion

        Args:
            client_socket (socket.socket): Socket connected to the client
            client_address (tuple): Client (ip_address, port) tuple

        Process:
            1. Perform SOCKS5 handshake (method negotiation)
            2. Parse request to get command, address, and port
            3. If CONNECT command, establish connection to destination
            4. If unsupported command, send error reply and close
            5. Handle any errors gracefully

        Error Handling:
            - Any exception during client handling is logged
            - Client socket is always closed before function exits
            - Errors in one client don't affect other clients
        """
        try:
            # Step 1: Perform SOCKS5 handshake
            # This negotiates authentication method with client
            from handlers import perform_handshake

            if not perform_handshake(client_socket):
                # Handshake failed, close connection
                client_socket.close()
                return

            # Step 2: Parse client request
            # Extract command, address type, destination address, and port
            from handlers import parse_request

            cmd, atyp, dst_addr, dst_port = parse_request(client_socket)

            # Step 3: Handle the command
            if cmd == CMD_CONNECT:
                # CONNECT command: establish TCP connection to destination
                from handlers import handle_connect

                handle_connect(client_socket, atyp, dst_addr, dst_port)
            else:
                # Unsupported command (BIND or UDP ASSOCIATE)
                logger.warning(f'Unsupported command: {cmd}')
                from handlers import send_reply

                send_reply(client_socket, REP_COMMAND_NOT_SUPPORTED)
                client_socket.close()

        except Exception as e:
            # Log any errors during client handling
            logger.error(f'Error handling client {client_address}: {e}')
            # Ensure client socket is closed
            try:
                client_socket.close()
            except Exception:
                pass

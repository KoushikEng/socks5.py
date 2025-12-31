# SOCKSv5 Proxy Server

A Python implementation of a SOCKSv5 proxy server compliant with RFC 1928.

## Features

- SOCKSv5 protocol support (RFC 1928)
- TCP CONNECT command
- IPv4 and domain name resolution
- No authentication (method 0x00)
- Multithreaded connection handling
- Non-blocking I/O with select()
- Detailed logging

## Requirements

- Python 3.6+
- Standard library only (no external dependencies)

## Installation

Clone the repository:
```bash
git clone https://github.com/KoushikEng/socks_v5.py.git
cd socks_v5.py
```

## Project Structure

```
SOCKSv5_server/
├── main.py              # Entry point for the server
├── server.py            # Main Socks5Server class
├── handlers.py          # Request parsing and connection handling
├── relay.py             # Bidirectional data relay
├── protocol.py          # SOCKS5 protocol constants
├── config.py            # Configuration and constants
└── README.md            # This file
```

### Module Descriptions

- **main.py**: Application entry point, initializes logging and starts the server
- **server.py**: Contains `Socks5Server` class that manages the server socket and accepts connections
- **handlers.py**: Implements SOCKS5 protocol handlers (handshake, request parsing, connection establishment)
- **relay.py**: Handles bidirectional data relay between client and remote sockets using `select()`
- **protocol.py**: SOCKS5 protocol constants (version, commands, address types, reply codes)
- **config.py**: Server configuration (host, port, buffer sizes, timeouts, logging)

## Usage

### Start the Server

```bash
python main.py
```

The server will start listening on `0.0.0.0:1080` by default.

### Custom Host/Port

Edit the `DEFAULT_HOST` and `DEFAULT_PORT` in `config.py`:
```python
DEFAULT_HOST = '127.0.0.1'
DEFAULT_PORT = 9999
```

Or modify the server initialization in `main.py`:
```python
server = Socks5Server(host='127.0.0.1', port=9999)
```

## Testing

### Using curl

```bash
curl --socks5 127.0.0.1:1080 http://example.com
```

For remote DNS resolution (DNS requests go through proxy):
```bash
curl --socks5-hostname 127.0.0.1:1080 http://example.com
```

### Using Firefox

1. Open Firefox Settings
2. Network Settings > Manual proxy configuration
3. SOCKS Host: `127.0.0.1`, Port: `1080`
4. Select `SOCKS v5`
5. Enable "Proxy DNS when using SOCKS v5"

### Using Chromium/Chrome

```bash
chromium --proxy-server="socks5://127.0.0.1:1080"
```

### Using Python requests

```python
import requests

proxies = {
   'http': 'socks5://127.0.0.1:1080',
   'https': 'socks5://127.0.0.1:1080'
}

response = requests.get('http://example.com', proxies=proxies)
print(response.text)
```

## Protocol Implementation

### Supported Features

| Feature | Status |
|---------|--------|
| TCP CONNECT | ✓ Supported |
| IPv4 | ✓ Supported |
| Domain names | ✓ Supported |
| IPv6 | ✓ Supported |
| UDP ASSOCIATE | ✗ Not implemented |
| BIND | ✗ Not implemented |
| No authentication | ✓ Supported |
| Username/Password auth | ✗ Not implemented |

### SOCKS5 Handshake Flow

1. **Client Greeting** (client → server)
   - VER (0x05)
   - NMETHODS (number of supported methods)
   - METHODS (list of method codes)

2. **Server Selection** (server → client)
   - VER (0x05)
   - METHOD (selected method or 0xFF if none)

3. **Client Request** (client → server)
   - VER (0x05)
   - CMD (0x01=CONNECT, 0x02=BIND, 0x03=UDP ASSOCIATE)
   - RSV (0x00)
   - ATYP (0x01=IPv4, 0x03=Domain, 0x04=IPv6)
   - ADDR (destination address)
   - PORT (destination port)

4. **Server Reply** (server → client)
   - VER (0x05)
   - REP (0x00=Success or error code)
   - RSV (0x00)
   - ATYP (address type of bound address)
   - BND.ADDR (bound address)
   - BND.PORT (bound port)

## Logging

The server logs to stdout with the following format:
```
2025-12-30 12:34:56 - INFO - SOCKS5 server listening on 0.0.0.0:1080
2025-12-30 12:34:57 - INFO - New connection from 192.168.1.100:54321
2025-12-30 12:34:57 - INFO - CONNECT to example.com:80
2025-12-30 12:34:57 - INFO - Connected to example.com:80
```

## Architecture

The server is organized into modular components with clear responsibilities:

### main.py
- `setup_logging()`: Configure logging format and level
- `main()`: Initialize server and start accepting connections

### server.py
- `Socks5Server`: Main server class
  - `__init__()`: Initialize server with host and port
  - `start()`: Create socket, bind, listen, and accept connections
  - `handle_client()`: Handle a single client connection in a thread

### handlers.py
- `perform_handshake()`: SOCKS5 handshake and method negotiation
- `parse_request()`: Parse client request to extract command, address, and port
- `send_reply()`: Send SOCKS5 reply messages to client
- `handle_connect()`: Handle CONNECT command by establishing connection to destination

### relay.py
- `relay_data()`: Bidirectional data relay between client and remote sockets using non-blocking I/O

### protocol.py
- SOCKS5 protocol constants (version, commands, address types, reply codes)
- Protocol-specific values defined per RFC 1928

### config.py
- Server configuration (host, port, buffer sizes, timeouts)
- Logging configuration
- Socket and threading options

## Limitations

- No authentication support
- UDP ASSOCIATE and BIND commands not implemented
- No connection pooling or caching
- No access control lists (ACLs)
- No bandwidth limiting

## Security Considerations

- This server accepts connections from any client
- No authentication is performed
- All traffic is unencrypted
- Use SSH dynamic forwarding for encrypted tunneling:
  ```bash
  ssh -D 1080 -N user@remote-server
  ```
- Consider adding authentication and access control for production use

## Development

### Adding Authentication

To add username/password authentication, implement method 0x02:

```python
def handle_auth(self, client_socket):
    version = client_socket.recv(1)[0]
    ulen = client_socket.recv(1)[0]
    username = client_socket.recv(ulen).decode()
    plen = client_socket.recv(1)[0]
    password = client_socket.recv(plen).decode()
    
    if self.authenticate(username, password):
        client_socket.sendall(struct.pack('!BB', 0x01, 0x00))
        return True
    else:
        client_socket.sendall(struct.pack('!BB', 0x01, 0x01))
        return False
```

### Adding UDP ASSOCIATE

Create a UDP socket, bind to a port, and return the address to the client. Relay UDP packets between client and destination.

## License

MIT License

## References

- RFC 1928: SOCKS Protocol Version 5
- https://www.rfc-editor.org/rfc/rfc1928.html

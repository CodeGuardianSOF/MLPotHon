import socket
import logging
import time
from datetime import datetime
import json
import os
import hashlib
import importlib.util
import selectors
import ipaddress
import re

# Set up logging
log_path = os.path.join(os.path.dirname(__file__), '../logs/honeypot.log')
security_log_path = os.path.join(os.path.dirname(__file__), '../logs/security_warning.log')
os.makedirs(os.path.dirname(log_path), exist_ok=True)
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
honeypot_logger = logging.getLogger('honeypot')
honeypot_logger.addHandler(logging.FileHandler(log_path))
security_logger = logging.getLogger('security')
security_logger.addHandler(logging.FileHandler(security_log_path))

class HoneypotServer:
    def __init__(self, honeypot_logger, security_logger, config_path='../cfg/honeypot_config.json'):
        self.honeypot_logger = honeypot_logger
        self.security_logger = security_logger
        config_path = os.path.join(os.path.dirname(__file__), config_path)
        self.load_config(config_path)
        self.services = self.load_handlers()
        self.selector = selectors.DefaultSelector()
        self.rate_limit = {}
        self.rate_limit_window = 60
        self.rate_limit_threshold = 100
        self.suspicious_patterns = [
            re.compile(b'\x90{100,}'),  # NOP sleds
            re.compile(b'cmd.exe'),  # Command execution
            re.compile(b'/bin/sh'),  # Shell execution
            re.compile(b'rootkit'),  # Rootkit signatures
        ]

    def load_config(self, config_path):
        try:
            with open(config_path) as config_file:
                config = json.load(config_file)
            self.host = config.get('host', '0.0.0.0')
            self.ports = config.get('ports', [80, 21, 22, 23, 25, 110])
            self.payload_storage_path = os.path.join(os.path.dirname(__file__), 'captures/payloads/')
            self.session_metadata_path = os.path.join(os.path.dirname(__file__), 'captures/sessions/')
            self.allowed_networks = [ipaddress.ip_network(net) for net in config.get('allowed_networks', ['0.0.0.0/0'])]
            os.makedirs(self.payload_storage_path, exist_ok=True)
            os.makedirs(self.session_metadata_path, exist_ok=True)
        except Exception as e:
            self.security_logger.error(f"Failed to load configuration: {e}")
            raise

    def load_handlers(self):
        handlers = {}
        handler_dir = os.path.join(os.path.dirname(__file__), '../handlers')
        
        for port in self.ports:
            module_name = f"handlers.{port}"
            handler_path = os.path.join(handler_dir, f"{port}.py")
            
            if os.path.isfile(handler_path):
                self.honeypot_logger.debug(f"Found handler file for port {port} at {handler_path}")
                spec = importlib.util.spec_from_file_location(module_name, handler_path)
                module = importlib.util.module_from_spec(spec)
                try:
                    spec.loader.exec_module(module)
                    handler_func = getattr(module, f"handle_{port}", None)
                    if handler_func:
                        handlers[port] = handler_func
                        self.honeypot_logger.info(f"Loaded handler for port {port}")
                    else:
                        self.honeypot_logger.warning(f"No handler function found in {handler_path}")
                except Exception as e:
                    self.security_logger.error(f"Failed to load handler for port {port}: {e}")
            else:
                self.honeypot_logger.warning(f"No handler file found for port {port}")
        
        return handlers
    
    def start(self):
        for port in self.ports:
            self.listen_on_port(port)
        while True:
            events = self.selector.select()
            for key, mask in events:
                callback = key.data
                callback(key.fileobj, mask)

    def listen_on_port(self, port):
        try:
            self.honeypot_logger.debug(f"Attempting to create socket for port {port}")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.honeypot_logger.debug(f"Binding socket to {self.host}:{port}")
            s.bind((self.host, port))
            s.listen(5)
            s.setblocking(False)
            self.honeypot_logger.debug(f"Registering socket {s} with selector")
            self.selector.register(s, selectors.EVENT_READ, self.accept_connection)
            self.honeypot_logger.info(f"Listening on port {port}...")
        except Exception as e:
            self.security_logger.critical(f"Failed to listen on port {port}: {e}")
            self.honeypot_logger.error(f"Exception in listen_on_port: {e}")
            raise

    def accept_connection(self, sock, mask):
        conn = None
        try:
            self.honeypot_logger.debug(f"Attempting to accept connection on socket {sock}")
            conn, addr = sock.accept()
            self.honeypot_logger.info(f"Accepted connection from {addr}")
            conn.setblocking(False)
            if not self.is_allowed(addr[0]):
                self.honeypot_logger.warning(f"Disallowed IP {addr[0]}. Closing connection.")
                conn.close()
                self.security_logger.warning(f"Connection from disallowed IP {addr[0]} closed.")
                return
            if self.rate_limit_exceeded(addr[0]):
                self.honeypot_logger.warning(f"Rate limit exceeded for IP {addr[0]}. Closing connection.")
                conn.close()
                self.security_logger.warning(f"Rate limit exceeded for IP {addr[0]}. Connection closed.")
                return
            port = sock.getsockname()[1]
            if port in self.services:
                self.honeypot_logger.info(f"Handler found for port {port}. Registering handler.")
                self.honeypot_logger.debug(f"Registering connection {conn} with selector")
                self.selector.register(conn, selectors.EVENT_READ, self.create_handler(self.services[port], conn, addr))
                self.log_connection_start(addr, port)
            else:
                self.honeypot_logger.warning(f"No handler for port {port}. Closing connection from {addr}.")
                conn.close()
        except Exception as e:
            self.security_logger.error(f"Error accepting connection: {e}")
            self.honeypot_logger.error(f"Error accepting connection: {e}")
            if conn:
                self.cleanup_socket(conn)

    def create_handler(self, handler, conn, addr):
        def wrapped_handler(sock, mask):
            start_time = datetime.now()
            try:
                self.honeypot_logger.info(f"Handling connection from {addr}")
                data = sock.recv(1024)
                if data:
                    self.honeypot_logger.debug(f"Received data from {addr}: {data}")
                    handler(conn, addr, self)
                    self.capture_payload(addr, data)
                else:
                    self.honeypot_logger.info(f"No data received. Closing connection from {addr}")
                    self.cleanup_socket(sock)
                    self.log_connection_end(addr, start_time)
            except BlockingIOError as e:
                self.honeypot_logger.warning(f"Non-blocking socket operation could not be completed immediately for {addr}: {e}")
            except UnicodeDecodeError as e:
                self.security_logger.error(f"Decoding error handling connection from {addr}: {e}")
                self.honeypot_logger.error(f"Decoding error handling connection from {addr}: {e}")
                self.cleanup_socket(sock)
            except Exception as e:
                self.security_logger.error(f"Error handling connection from {addr}: {e}")
                self.honeypot_logger.error(f"Error handling connection from {addr}: {e}")
                self.cleanup_socket(sock)
        return wrapped_handler
    
    def cleanup_socket(self, sock):
        """Unregister and close the socket safely."""
        try:
            self.selector.unregister(sock)
        except Exception as e:
            self.honeypot_logger.error(f"Error unregistering socket: {e}")
        try:
            sock.close()
        except Exception as e:
            self.honeypot_logger.error(f"Error closing socket: {e}")
    
    def is_allowed(self, ip):
        """Check if the IP is allowed to connect."""
        ip_addr = ipaddress.ip_address(ip)
        return any(ip_addr in net for net in self.allowed_networks)

    def rate_limit_exceeded(self, ip):
        """Check if the rate limit is exceeded for the IP."""
        current_time = time.time()
        if ip not in self.rate_limit:
            self.rate_limit[ip] = []
        self.rate_limit[ip] = [t for t in self.rate_limit[ip] if t > current_time - self.rate_limit_window]
        if len(self.rate_limit[ip]) >= self.rate_limit_threshold:
            return True
        self.rate_limit[ip].append(current_time)
        return False

    def capture_payload(self, addr, data):
        """Capture and store payload data for further analysis."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_hash = hashlib.md5(data).hexdigest()
        filename = os.path.join(self.payload_storage_path, f"{addr[0]}_{timestamp}_{file_hash}.bin")
        with open(filename, 'wb') as f:
            f.write(data)
        self.honeypot_logger.info(f"Captured payload from {addr} stored in {filename}")
        self.store_metadata(addr, filename)
        self.analyze_payload(addr, data)

    def store_metadata(self, addr, payload_filename):
        """Store metadata related to the captured payload."""
        metadata = {
            'source_ip': addr[0],
            'source_port': addr[1],
            'timestamp': datetime.now().isoformat(),
            'payload_filename': payload_filename,
        }
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        metadata_filename = f"{self.session_metadata_path}/{addr[0]}_{timestamp}.json"
        with open(metadata_filename, 'w') as f:
            json.dump(metadata, f)
        self.honeypot_logger.info(f"Metadata stored in {metadata_filename}")

    def log_connection_start(self, addr, port):
        self.honeypot_logger.info(f"Connection started from {addr} on port {port}")

    def log_connection_end(self, addr, start_time):
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        self.honeypot_logger.info(f"Connection from {addr} ended. Duration: {duration:.2f} seconds")

    def analyze_payload(self, addr, data):
        """Analyze the payload for suspicious patterns and log warnings if detected."""
        for pattern in self.suspicious_patterns:
            if pattern.search(data):
                self.security_logger.warning(f"Suspicious pattern detected in payload from {addr}")

if __name__ == "__main__":
    try:
        server = HoneypotServer(honeypot_logger, security_logger)
        server.start()
    except Exception as e:
        security_logger.critical(f"Failed to start HoneypotServer: {e}")
        honeypot_logger.critical(f"Failed to start HoneypotServer: {e}")

import socket
import threading
import logging
import time
from datetime import datetime
import json
import os
import hashlib

# Set up logging
log_path = 'logs/honeypot.log'
os.makedirs(os.path.dirname(log_path), exist_ok=True)
logging.basicConfig(filename=log_path, level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class HoneypotServer:
    def __init__(self, config_path='cfg/honeypot_config.json'):
        self.load_config(config_path)
        self.services = {
            80: self.handle_http,
            21: self.handle_ftp,
            22: self.handle_ssh,
            23: self.handle_telnet,
            25: self.handle_smtp,
            110: self.handle_pop3,
        }

    def load_config(self, config_path):
        with open(config_path) as config_file:
            config = json.load(config_file)
        self.host = config.get('host', '0.0.0.0')
        self.ports = config.get('ports', [80, 21, 22, 23, 25, 110])
        self.malware_storage_path = config.get('malware_storage_path', 'malware/')
        os.makedirs(self.malware_storage_path, exist_ok=True)

    def start(self):
        for port in self.ports:
            threading.Thread(target=self.listen_on_port, args=(port,)).start()

    def listen_on_port(self, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((self.host, port))
        s.listen(5)
        logging.info(f"Listening on port {port}...")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=self.services[port], args=(conn, addr)).start()

    def handle_http(self, conn, addr):
        start_time = datetime.now()
        self.log_connection_start(addr, 80)
        try:
            request = conn.recv(1024).decode()
            logging.debug(f"HTTP request details: {request}")
            response = "HTTP/1.1 200 OK\n\nWelcome to the HTTP honeypot"
            conn.sendall(response.encode())
            logging.info(f"HTTP response sent to {addr}")
            self.capture_payload(addr, request.encode())
        except Exception as e:
            logging.error(f"Error handling HTTP connection from {addr}: {e}")
        finally:
            conn.close()
            self.log_connection_end(addr, start_time)

    def handle_ftp(self, conn, addr):
        start_time = datetime.now()
        self.log_connection_start(addr, 21)
        welcome_message = "220 Welcome to the FTP honeypot\n"
        conn.sendall(welcome_message.encode())
        authenticated = False
        try:
            while True:
                command = conn.recv(1024).decode().strip()
                logging.debug(f"FTP command from {addr}: {command}")
                if command.lower().startswith('user'):
                    conn.sendall("331 Password required for user.\n".encode())
                elif command.lower().startswith('pass'):
                    conn.sendall("230 User logged in, proceed.\n".encode())
                    authenticated = True
                elif command.lower().startswith('stor'):
                    conn.sendall("150 Opening data connection.\n".encode())
                    data = conn.recv(1024)
                    self.capture_payload(addr, data)
                    conn.sendall("226 Transfer complete.\n".encode())
                elif command.lower() == 'quit':
                    conn.sendall("221 Goodbye.\n".encode())
                    break
                elif authenticated:
                    conn.sendall("200 Command okay.\n".encode())
                else:
                    conn.sendall("530 Not logged in.\n".encode())
        except Exception as e:
            logging.error(f"Error handling FTP command from {addr}: {e}")
        finally:
            conn.close()
            self.log_connection_end(addr, start_time)

    def handle_ssh(self, conn, addr):
        start_time = datetime.now()
        self.log_connection_start(addr, 22)
        try:
            fake_banner = "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb9u1\n"
            conn.sendall(fake_banner.encode())
            # Fake delay to simulate more realistic SSH interaction
            time.sleep(2)
            logging.debug(f"SSH banner sent to {addr}")
            data = conn.recv(1024)
            self.capture_payload(addr, data)
        except Exception as e:
            logging.error(f"Error handling SSH connection from {addr}: {e}")
        finally:
            conn.close()
            self.log_connection_end(addr, start_time)

    def handle_telnet(self, conn, addr):
        start_time = datetime.now()
        self.log_connection_start(addr, 23)
        try:
            welcome_message = "Welcome to the Telnet honeypot\n"
            conn.sendall(welcome_message.encode())
            while True:
                command = conn.recv(1024).decode().strip()
                logging.debug(f"Telnet command from {addr}: {command}")
                if command.lower() == 'exit':
                    conn.sendall("Goodbye!\n".encode())
                    break
                else:
                    conn.sendall(f"Received: {command}\n".encode())
                    self.capture_payload(addr, command.encode())
        except Exception as e:
            logging.error(f"Error handling Telnet connection from {addr}: {e}")
        finally:
            conn.close()
            self.log_connection_end(addr, start_time)

    def handle_smtp(self, conn, addr):
        start_time = datetime.now()
        self.log_connection_start(addr, 25)
        try:
            welcome_message = "220 Welcome to the SMTP honeypot\n"
            conn.sendall(welcome_message.encode())
            while True:
                command = conn.recv(1024).decode().strip()
                logging.debug(f"SMTP command from {addr}: {command}")
                if command.lower().startswith('helo'):
                    conn.sendall("250 Hello\n".encode())
                elif command.lower().startswith('mail from:'):
                    conn.sendall("250 OK\n".encode())
                elif command.lower().startswith('rcpt to:'):
                    conn.sendall("250 OK\n".encode())
                elif command.lower() == 'data':
                    conn.sendall("354 End data with <CR><LF>.<CR><LF>\n".encode())
                elif command.lower() == '.':
                    conn.sendall("250 OK\n".encode())
                elif command.lower() == 'quit':
                    conn.sendall("221 Bye\n".encode())
                    break
                else:
                    conn.sendall("500 Command not understood\n".encode())
                self.capture_payload(addr, command.encode())
        except Exception as e:
            logging.error(f"Error handling SMTP connection from {addr}: {e}")
        finally:
            conn.close()
            self.log_connection_end(addr, start_time)

    def handle_pop3(self, conn, addr):
        start_time = datetime.now()
        self.log_connection_start(addr, 110)
        try:
            welcome_message = "+OK POP3 server ready\n"
            conn.sendall(welcome_message.encode())
            while True:
                command = conn.recv(1024).decode().strip()
                logging.debug(f"POP3 command from {addr}: {command}")
                if command.lower() == 'quit':
                    conn.sendall("+OK Goodbye!\n".encode())
                    break
                elif command.lower() == 'user':
                    conn.sendall("+OK\n".encode())
                elif command.lower() == 'pass':
                    conn.sendall("+OK\n".encode())
                else:
                    conn.sendall("-ERR Command not recognized\n".encode())
                self.capture_payload(addr, command.encode())
        except Exception as e:
            logging.error(f"Error handling POP3 connection from {addr}: {e}")
        finally:
            conn.close()
            self.log_connection_end(addr, start_time)

    def capture_payload(self, addr, data):
        """Capture and store payload data for further analysis."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_hash = hashlib.md5(data).hexdigest()
        filename = f"{self.malware_storage_path}/{addr[0]}_{timestamp}_{file_hash}.bin"
        with open(filename, 'wb') as f:
            f.write(data)
        logging.info(f"Captured payload from {addr} stored in {filename}")
        self.store_metadata(addr, filename)

    def store_metadata(self, addr, filename):
        """Store metadata related to the captured payload."""
        metadata = {
            'source_ip': addr[0],
            'source_port': addr[1],
            'timestamp': datetime.now().isoformat(),
            'filename': filename,
        }
        metadata_filename = f"{filename}.json"
        with open(metadata_filename, 'w') as f:
            json.dump(metadata, f)
        logging.info(f"Metadata stored in {metadata_filename}")

    def handle_session(self, conn, addr, handler):
        self.start_time = datetime.now()
        session_data = []
        try:
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                session_data.append(data)
                handler(conn, addr, data)
        except Exception as e:
            logging.error(f"Error during session from {addr}: {e}")
        finally:
            conn.close()
            self.log_connection_end(addr)
            self.store_session(addr, session_data)

    def store_session(self, addr, session_data):
        """Store session data for further analysis."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        session_filename = f"{self.malware_storage_path}/{addr[0]}_{timestamp}_session.txt"
        with open(session_filename, 'wb') as f:
            for data in session_data:
                f.write(data)
        logging.info(f"Session data from {addr} stored in {session_filename}")

    def log_connection_start(self, addr, port):
        logging.info(f"Connection started from {addr} on port {port}")

    def log_connection_end(self, addr, start_time):
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        logging.info(f"Connection from {addr} ended. Duration: {duration:.2f} seconds")

    def start(self):
        for port in self.ports:
            threading.Thread(target=self.listen_on_port, args=(port,)).start()

    def listen_on_port(self, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((self.host, port))
        s.listen(5)
        logging.info(f"Listening on port {port}...")
        while True:
            conn, addr = s.accept()
            if port in self.services:
                threading.Thread(target=self.services[port], args=(conn, addr)).start()
            else:
                conn.close()
                logging.warning(f"No handler for port {port}. Connection from {addr} closed.")

if __name__ == "__main__":
    server = HoneypotServer()
    server.start()
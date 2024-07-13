import logging
from datetime import datetime

def handle_23(conn, addr, honeypot_server):
    start_time = datetime.now()
    honeypot_server.log_connection_start(addr, 23)
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
                honeypot_server.capture_payload(addr, command.encode())
    except Exception as e:
        logging.error(f"Error handling Telnet connection from {addr}: {e}")
    finally:
        conn.close()
        honeypot_server.log_connection_end(addr, start_time)

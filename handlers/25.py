import logging
from datetime import datetime

def handle_25(conn, addr, honeypot_server):
    start_time = datetime.now()
    honeypot_server.log_connection_start(addr, 25)
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
            honeypot_server.capture_payload(addr, command.encode())
    except Exception as e:
        logging.error(f"Error handling SMTP connection from {addr}: {e}")
    finally:
        conn.close()
        honeypot_server.log_connection_end(addr, start_time)

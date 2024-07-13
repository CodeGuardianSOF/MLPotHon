import logging
from datetime import datetime
import socket

def handle_21(conn, addr, honeypot_server):
    start_time = datetime.now()
    honeypot_server.log_connection_start(addr, 21)
    welcome_message = "220 Welcome to the FTP honeypot\n"
    conn.sendall(welcome_message.encode())
    logging.info(f"Sent welcome message to {addr}")
    authenticated = False
    try:
        while True:
            conn.settimeout(5)
            try:
                command = conn.recv(1024).decode().strip()
                if not command:
                    logging.debug(f"No command received from {addr}.")
                    break
                logging.debug(f"FTP command from {addr}: {command}")
                if command.lower().startswith('user'):
                    conn.sendall("331 Password required for user.\n".encode())
                    logging.info(f"Sent password required message to {addr}")
                elif command.lower().startswith('pass'):
                    conn.sendall("230 User logged in, proceed.\n".encode())
                    logging.info(f"Sent login successful message to {addr}")
                    authenticated = True
                elif command.lower().startswith('stor'):
                    conn.sendall("150 Opening data connection.\n".encode())
                    logging.info(f"Sent opening data connection message to {addr}")
                    data = conn.recv(1024)
                    honeypot_server.capture_payload(addr, data)
                    conn.sendall("226 Transfer complete.\n".encode())
                    logging.info(f"Sent transfer complete message to {addr}")
                elif command.lower() == 'quit':
                    conn.sendall("221 Goodbye.\n".encode())
                    logging.info(f"Sent goodbye message to {addr}")
                    break
                elif authenticated:
                    conn.sendall("200 Command okay.\n".encode())
                    logging.info(f"Sent command okay message to {addr}")
                else:
                    conn.sendall("530 Not logged in.\n".encode())
                    logging.info(f"Sent not logged in message to {addr}")
            except socket.timeout:
                logging.debug(f"Connection from {addr} timed out.")
                break
            except Exception as e:
                logging.error(f"Error handling FTP command from {addr}: {e}")
                break
    except Exception as e:
        logging.error(f"Unexpected error handling FTP connection from {addr}: {e}")
    finally:
        conn.close()
        honeypot_server.log_connection_end(addr, start_time)
        logging.info(f"Connection from {addr} ended. Duration: {datetime.now() - start_time}")

import logging
from datetime import datetime

def handle_80(conn, addr, honeypot_server):
    start_time = datetime.now()
    honeypot_server.log_connection_start(addr, 80)
    try:
        request = conn.recv(1024).decode()
        logging.debug(f"HTTP request details: {request}")
        response = "HTTP/1.1 200 OK\n\nWelcome to the HTTP honeypot"
        conn.sendall(response.encode())
        logging.info(f"HTTP response sent to {addr}")
        honeypot_server.capture_payload(addr, request.encode())
    except BlockingIOError as e:
        logging.warning(f"Non-blocking socket operation could not be completed immediately for {addr}: {e}")
    except Exception as e:
        logging.error(f"Error handling HTTP connection from {addr}: {e}")
    finally:
        conn.close()
        honeypot_server.log_connection_end(addr, start_time)

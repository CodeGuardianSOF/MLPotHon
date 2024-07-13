import logging
from datetime import datetime
import time

def handle_22(conn, addr, honeypot_server):
    start_time = datetime.now()
    honeypot_server.log_connection_start(addr, 22)
    try:
        fake_banner = "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb9u1\r\n"
        conn.sendall(fake_banner.encode())
        # Fake delay to simulate more realistic SSH interaction
        time.sleep(2)
        honeypot_server.honeypot_logger.debug(f"SSH banner sent to {addr}")

        data = conn.recv(1024)
        if data:
            honeypot_server.capture_payload(addr, data)
        else:
            honeypot_server.honeypot_logger.info(f"No data received from {addr}")
    except Exception as e:
        honeypot_server.security_logger.error(f"Error handling SSH connection from {addr}: {e}")
    finally:
        honeypot_server.selector.unregister(conn)
        conn.close()
        honeypot_server.log_connection_end(addr, start_time)

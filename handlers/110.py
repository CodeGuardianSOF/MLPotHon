import time
from datetime import datetime

def handle_110(conn, addr, server):
    server.log_connection_start(addr, 110)
    start_time = datetime.now()
    
    def send_response(message):
        conn.send(f"{message}\r\n".encode())
    
    messages = [
        {"id": 1, "size": 160, "content": "Subject: Test Message 1\r\n\r\nThis is a test message 1."},
        {"id": 2, "size": 160, "content": "Subject: Test Message 2\r\n\r\nThis is a test message 2."},
    ]
    
    authenticated = False
    send_response("+OK POP3 server ready")

    try:
        while True:
            data = conn.recv(1024).decode()
            if not data:
                break

            command, *args = data.strip().split()
            command = command.upper()
            
            if command == 'USER':
                if args:
                    user = args[0]
                    send_response("+OK User accepted")
                else:
                    send_response("-ERR No user name provided")
            elif command == 'PASS':
                if args:
                    password = args[0]
                    authenticated = True
                    send_response("+OK Pass accepted")
                else:
                    send_response("-ERR No password provided")
            elif command == 'STAT' and authenticated:
                total_size = sum(msg["size"] for msg in messages)
                send_response(f"+OK {len(messages)} {total_size}")
            elif command == 'LIST' and authenticated:
                send_response(f"+OK {len(messages)} messages")
                for msg in messages:
                    send_response(f"{msg['id']} {msg['size']}")
                send_response(".")
            elif command == 'RETR' and authenticated:
                if args:
                    msg_id = int(args[0])
                    message = next((msg for msg in messages if msg["id"] == msg_id), None)
                    if message:
                        send_response(f"+OK {message['size']} octets")
                        send_response(message["content"])
                        send_response(".")
                    else:
                        send_response("-ERR No such message")
                else:
                    send_response("-ERR No message number provided")
            elif command == 'DELE' and authenticated:
                if args:
                    msg_id = int(args[0])
                    message = next((msg for msg in messages if msg["id"] == msg_id), None)
                    if message:
                        messages.remove(message)
                        send_response("+OK Message deleted")
                    else:
                        send_response("-ERR No such message")
                else:
                    send_response("-ERR No message number provided")
            elif command == 'QUIT':
                send_response("+OK POP3 server signing off")
                break
            else:
                send_response("-ERR Unknown command")

            server.capture_payload(addr, data.encode())
    finally:
        conn.close()
        server.log_connection_end(addr, start_time)
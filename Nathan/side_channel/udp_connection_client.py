import socket
import time

def main():
    server_ip = "10.13.37.5"
    server_port = 12345
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    

    while True:
        message = "Ping"
        sock.sendto(message.encode(), (server_ip, server_port))
        sender_port = sock.getsockname()[1]
        print(f"Sent: {message} on {sender_port}")
        data, addr = sock.recvfrom(1024)
        print(f"Received: {data.decode()} from {addr}")
        time.sleep(1)

if __name__ == "__main__":
    main()

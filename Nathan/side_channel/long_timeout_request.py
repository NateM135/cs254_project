from scapy import *

my_ip = '10.13.37.6'
my_port = 9999

resolver_ip = '10.13.37.9'
resolver_port = 53

domain_name = "attack.me"
DNS_QUERY_TIMEOUT = 10000

ip_layer = IP(dst=resolver_ip, src=my_ip)
udp_layer = UDP(dport=resolver_port, sport=my_port)
dns_layer = DNS(rd=1, qd=DNSQR(qname=domain_name))
packet = ip_layer / udp_layer / dns_layer
send(packet, timeout=DNS_QUERY_TIMEOUT)
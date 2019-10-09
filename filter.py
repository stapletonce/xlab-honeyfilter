# Filter out "noise" packets from internet
# Using Scapy

from scapy.all import *

# take in a packet - start with just reading from a pcap file
packets = rdpcap('example.pcapng')

# write packets to a pcap file, ignoring the ones to be "filtered out"
count = 0;
for pkt in packets:
    if not (pkt.haslayer(ARP)):
        wrpcap('filtered.pcap', pkt, append=True)
    else:
        count+=1

print("Filtered out " + str(count) + " packets")

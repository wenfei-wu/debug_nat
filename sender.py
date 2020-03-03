from scapy.all import *

PCAPFILE="ten.pcap"

f=rdpcap(PCAPFILE)
idx = 0

#cnt=100
#while cnt>0:
#    sendp(f[idx])
#    cnt-=1

f[idx].show()
f[idx].pdfdump("pkt_"+str(idx)+".pdf")

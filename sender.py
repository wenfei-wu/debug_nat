from scapy.all import *

PCAPFILE=""

f=rdpcap(PCAPFILE)
idx = 1

cnt=100
while cnt>0:
    sendp(f[idx])
    cnt-=1

f[idx].show()
f[idx].dumppdf("pkt_"+str(idx)+".pdf")

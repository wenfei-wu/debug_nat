from scapy.all import *

PCAPFILE="ten.pcap"
IFACE="p9p1"
IDX=4

#sendp(IP(ttl=10), iface=IFACE)


f=rdpcap(PCAPFILE)

pkt = f[IDX]

new_pkt =


#for pkt in f:
#    pkt.show()

cnt=100
while cnt>0:
    sendp(pkt, iface=IFACE)
    cnt-=1

#f[idx].show()
#f[idx].dumppdf("pkt_"+str(idx)+".pdf")

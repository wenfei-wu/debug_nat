from scapy.all import *

PCAPFILE="univ1_pt1.pcap"
#IFACE="p9p1"
#IDX=0



f=rdpcap(PCAPFILE)
pkts = [pkt if IP not in pkt else pkt/('a'*max(0, pkt[IP].len-len(pkt[IP]))) for pkt in f]
wrpcap("univ1_pt1_complete.pcap", pkts)

#pkt = f[IDX]
#pkt.show()
#print(len(pkt))
#print(len(pkt[IP]))
#print(pkt[IP].len)
#print(len(pkt[TCP]))
#pkt = pkt/('a'* (pkt[IP].len-len(pkt[IP])  ))
#print(pkt)
#print(len(pkt))
#print(pkt.time)



#wrpcap("pkt_0_aug.pcap", (pkt))

#for pkt in f:
#    pkt.show()

#cnt=100
#while cnt>0:
#    sendp(pkt, iface=IFACE)
#    cnt-=1

#f[idx].show()
#f[idx].pdfdump("pkt_"+str(idx)+".pdf")

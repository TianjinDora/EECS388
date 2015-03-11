import dpkt
import sys
import sys

#filename = 'C:\Users\\nathan\Downloads\lbl-internal.20041004-1305.port002.dump.anon'
filename = sys.argv[1]
f = open(filename, "rb")
pcap = dpkt.pcap.Reader(f)

ipCounts = {}

for ts, buf in pcap:
    try: eth = dpkt.ethernet.Ethernet(buf)
    except dpkt.UnpackError: continue
        
    if eth.type != dpkt.ethernet.ETH_TYPE_IP: continue # if not IP packet, continue
    ip = eth.data

    # only process TCP packets
    if ip.p == dpkt.ip.IP_PROTO_TCP:
        packet = ip.data


        if packet.flags & dpkt.tcp.TH_SYN != 0: # if it's a SYN packet
            # initialize in dictionary if it doesn't exist
            if ip.src not in ipCounts: ipCounts[ip.src] = {'SYN': 0, 'SYNACK': 0}
            if ip.dst not in ipCounts: ipCounts[ip.dst] = {'SYN': 0, 'SYNACK': 0}
            
            if packet.flags & dpkt.tcp.TH_ACK != 0: # if it's an ACK packet too
                ipCounts[ip.dst]['SYNACK'] += 1
            else:
                ipCounts[ip.src]['SYN'] += 1

#print ipCounts

#for item in ipCounts.items(): print item

for item in ipCounts.items():
    if item[1]['SYN'] > item[1]['SYNACK'] * 3:
        hexstring = str(item[0].encode('hex'))
        num = [hexstring[i:i+2] for i in range(0,len(hexstring), 2)]
        string = ''
        for x in num:
            string = string + str(int(x,16)) + '.'
        print string[:-1]

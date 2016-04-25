#!/usr/local/bin/python2.7

import dpkt, socket

counter=0
ipcounter=0
tcpcounter=0
udpcounter=0
dns_query_counter = 0
dns_response_counter = 0

filename='../wired_android/wired_android_amazon.com_1329408440.26.pcap'
domain = "amazon.com"

events_dict = {}

for ts, pkt in dpkt.pcap.Reader(open(filename,'r')):

    counter+=1
    eth=dpkt.ethernet.Ethernet(pkt) 
    if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
        continue

    ip=eth.data
    ipcounter+=1

    # http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
    if ip.p == dpkt.ip.IP_PROTO_TCP: 
        tcpcounter+=1

    if ip.p == dpkt.ip.IP_PROTO_UDP:
        udpcounter += 1
        udp = ip.data

        # ensure this is DNS packet
        if udp.sport != 53 and udp.dport != 53:
            continue
        dns = dpkt.dns.DNS(udp.data)
        if dns.qr == dpkt.dns.DNS_Q: # DNS query packet
            if dns.opcode != dpkt.dns.DNS_QUERY:
                print "? no DNS_QUERY, opcode: ", dns.opcode
                continue
            if len(dns.qd) != 1:
                continue
            if len(dns.an) != 0:
                continue
            if len(dns.ns) != 0:
                continue
            if dns.qd[0].cls != dpkt.dns.DNS_IN:
                continue
            if dns.qd[0].type != dpkt.dns.DNS_A:
                continue
            print dns.id, "DNS query:", dns.qd[0].name
            
            events_dict["DNS_" + dns.id] = {"src": ip.src, "dst": ip.dst, "start_ts": ts, "end_ts": 0,
                                            "bytes_involved": ip.len, "packets_involved": 1,
                                            "ACK_num": 0, "loss_packets": 0}
            dns_query_counter += 1
        else: # DNS reply packet
            if dns.opcode != dpkt.dns.DNS_QUERY:
                print "? no DNS_QUERY, opcode: ", dns.opcode
                continue
            if dns.rcode != dpkt.dns.DNS_RCODE_NOERR:
                continue
            if len(dns.an) < 1:
                continue
            
            dns_response_counter += 1
            # process and spit out responses based on record type
            # ref: http://en.wikipedia.org/wiki/List_of_DNS_record_types
            for answer in dns.an:
                if answer.type == dpkt.dns.DNS_CNAME:
                    pass#print dns.id, "CNAME request", answer.name, "\tresponse", answer.cname
                elif answer.type == dpkt.dns.DNS_A:
                    print dns.id, "A request", answer.name, "\tresponse", socket.inet_ntoa(answer.rdata)
                elif answer.type == dpkt.dns.DNS_PTR:
                    pass#print dns.id, "PTR request", answer.name, "\tresponse", answer.ptrname
            events_dict["DNS_" + dns.id]["end_ts"] = ts
            events_dict["DNS_" + dns.id]["bytes_involved"] += ip.len
            events_dict["DNS_" + dns.id]["packets_involved"] += 1

print "Total number of packets in the pcap file: ", counter
print "Total number of ip packets: ", ipcounter
print "Total number of tcp packets: ", tcpcounter
print "Total number of udp packets: ", udpcounter

print "**************"
for event_name, event_record in events_dict.iteritems():
    if event_name[:3] == "DNS":
        print '<DNS request, %s, %s, %s, %s, %d, %d>' % \
                (event_record["src"], event_record["dst"], event_record["start_ts"], event_record["end_ts"],
                event_record["bytes_involved"], event_record["packets_involved"])
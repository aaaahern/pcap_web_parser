#!/usr/local/bin/python2.7

import dpkt
import socket
from collections import OrderedDict 
from argparse import ArgumentParser


TCP_FIRST_HANDSHAKE = 1
TCP_SECOND_HANDSHAKE = 2 
TCP_ESTABLISHED = 3

my_ip = ""

trace = False

def set_my_ip(ip):
    global my_ip
    global trace
    if trace:
        print "*** Set my ip as:", ip
    my_ip = ip

def parse(filename, trace_opt=False):
    global trace
    trace = trace_opt
    counter = 0
    dns_query_counter = 0
    dns_response_counter = 0
    

    events_dict = OrderedDict()
    dst_ip_set = set()
    tcp_conn_info = {}

    for ts, pkt in dpkt.pcap.Reader(open(filename,'r')):

        counter += 1
        eth = dpkt.ethernet.Ethernet(pkt)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue

        ip = eth.data

        src_ip = socket.inet_ntoa(ip.src)
        dst_ip = socket.inet_ntoa(ip.dst)

        # http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
        if my_ip != "" and ip.p == dpkt.ip.IP_PROTO_TCP: 
            if src_ip not in dst_ip_set and dst_ip not in dst_ip_set:
                if trace:
                    print "TCP packet from/to unknown IP, ignore."
                continue
            
            tcp = ip.data

            if my_ip == src_ip:
                connection_name = src_ip + ':' + str(tcp.sport) + '-' + dst_ip + ':' + str(tcp.dport)
            else:
                connection_name = dst_ip + ':' + str(tcp.dport) + '-' + src_ip + ':' + str(tcp.sport)

            # ignore connection finish packet
            if tcp.flags & dpkt.tcp.TH_FIN:
                # print "finish packet "
                continue

            # first handshake
            if connection_name not in tcp_conn_info:
                if tcp.flags & dpkt.tcp.TH_SYN and not tcp.ack:    
                    if trace:  
                        print "* new TCP connection: %s" % connection_name
                    event_name = "TCPCONN_" + connection_name
                    events_dict[event_name] = {"src": src_ip, "dst": dst_ip,
                                               "start_ts": ts, "end_ts": 0,
                                               "bytes_involved": ip.len, "packets_involved": 1,
                                               "ACK_num": 0, "loss_packets": 0}
                    tcp_conn_info[connection_name] = {}
                    tcp_conn_info[connection_name]["src_wait_ack"] = [tcp.seq]
                    tcp_conn_info[connection_name]["src_init_seq"] = tcp.seq
                    tcp_conn_info[connection_name]["status"] = TCP_FIRST_HANDSHAKE
                    tcp_conn_info[connection_name]["request_counter"] = 0
                else:
                    if trace:
                        print "Error: No TCP establishment record for this connection, ignore"
                    continue

            # second handshake
            elif tcp.flags & dpkt.tcp.TH_SYN and tcp.ack:
                if tcp_conn_info[connection_name]["status"] == TCP_FIRST_HANDSHAKE:
                    # print "second handshake"
                    event_name = "TCPCONN_" + connection_name
                    events_dict[event_name]["bytes_involved"] += ip.len
                    events_dict[event_name]["packets_involved"] += 1
                    events_dict[event_name]["ACK_num"] += 1
                    tcp_conn_info[connection_name]["src_wait_ack"].remove(tcp.ack - 1)
                    tcp_conn_info[connection_name]["dst_wait_ack"] = [tcp.seq]
                    tcp_conn_info[connection_name]["dst_init_seq"] = tcp.seq
                    tcp_conn_info[connection_name]["status"] = TCP_SECOND_HANDSHAKE
                else:
                    if trace:
                        print "Error: duplicate second handshake packet"
                    tcp_conn_info[connection_name]["loss_packets"] += 1

            # third handshake, connection established
            elif tcp_conn_info[connection_name]["status"] == TCP_SECOND_HANDSHAKE and \
                 len(tcp.data) == 0:
                if trace:
                    print "TCP connection established"
                event_name = "TCPCONN_" + connection_name
                events_dict[event_name]["end_ts"] = ts
                events_dict[event_name]["bytes_involved"] += ip.len
                events_dict[event_name]["packets_involved"] += 1
                events_dict[event_name]["ACK_num"] += 1
                tcp_conn_info[connection_name]["dst_wait_ack"].remove(tcp.ack - 1)
                tcp_conn_info[connection_name]["status"] = TCP_ESTABLISHED

            # data transmition
            elif tcp_conn_info[connection_name]["status"] == TCP_ESTABLISHED:
                # src -> dst
                if tcp.dport == 80:
                    # HTTP request
                    if len(tcp.data) > 0:
                        # print "seq", tcp.seq, "len", len(tcp.data)
                        if tcp.seq + len(tcp.data) not in tcp_conn_info[connection_name]["src_wait_ack"]:
                            tcp_conn_info[connection_name]["request_counter"] += 1
                            tcp_conn_info[connection_name]["src_wait_ack"].append(tcp.seq + len(tcp.data))
                            # http_request = dpkt.http.Request(tcp.data)
                            if trace:
                                print "- new object request"
                            # print "- new object request", http_request.uri
                            event_name = "OBJREQ_" + connection_name + '_' + \
                                         str(tcp_conn_info[connection_name]["request_counter"])
                            events_dict[event_name] = {"src": src_ip, "dst": dst_ip,
                                                       "start_ts": ts, "end_ts": 0,
                                                       "bytes_involved": ip.len, "packets_involved": 1,
                                                       "ACK_num": 0, "loss_packets": 0}
                            # print tcp_conn_info[connection_name]["src_wait_ack"]
                        else:
                            if trace:
                                print "Retransmit HTTP request"
                            event_name = "OBJREQ_" + connection_name + '_' + \
                                         str(tcp_conn_info[connection_name]["request_counter"])
                            events_dict[event_name]["loss_packets"] += 1

                    # HTTP response ACK
                    else:
                        if tcp.ack in tcp_conn_info[connection_name]["dst_wait_ack"]:
                            # print "ack"
                            tcp_conn_info[connection_name]["dst_wait_ack"].remove(tcp.ack)
                            event_name = "OBJREQ_" + connection_name + '_' + \
                                         str(tcp_conn_info[connection_name]["request_counter"])
                            events_dict[event_name]["ACK_num"] += 1
                            events_dict[event_name]["packets_involved"] += 1
                            events_dict[event_name]["bytes_involved"] += ip.len
                            events_dict[event_name]["end_ts"] = ts
                        elif len(tcp_conn_info[connection_name]["dst_wait_ack"]) == 0 or \
                             tcp.ack > max(tcp_conn_info[connection_name]["dst_wait_ack"]):
                            continue
                        else:
                            if trace:
                                print "Retransmit HTTP response ACK", tcp.ack
                            event_name = "OBJREQ_" + connection_name + '_' + \
                                         str(tcp_conn_info[connection_name]["request_counter"])
                            events_dict[event_name]["loss_packets"] += 1
                            events_dict[event_name]["packets_involved"] += 1

                # des -> src
                elif tcp.sport == 80:
                    # HTTP response
                    if len(tcp.data) > 0:
                        # print "seq", tcp.seq, "len", len(tcp.data)
                        if tcp.seq + len(tcp.data) not in tcp_conn_info[connection_name]["dst_wait_ack"]:
                            tcp_conn_info[connection_name]["dst_wait_ack"].append(tcp.seq + len(tcp.data))
                            event_name = "OBJREQ_" + connection_name + '_' + \
                                         str(tcp_conn_info[connection_name]["request_counter"])
                            events_dict[event_name]["packets_involved"] += 1
                            events_dict[event_name]["bytes_involved"] += ip.len
                            # print tcp_conn_info[connection_name]["dst_wait_ack"]
                        else:
                            if trace:
                                print "Retransmit HTTP response"
                            event_name = "OBJREQ_" + connection_name + '_' + \
                                         str(tcp_conn_info[connection_name]["request_counter"])
                            events_dict[event_name]["loss_packets"] += 1

                    # HTTP request ACK
                    else:
                        if tcp.ack in tcp_conn_info[connection_name]["src_wait_ack"]:
                            # print "ack"
                            tcp_conn_info[connection_name]["src_wait_ack"].remove(tcp.ack)
                            event_name = "OBJREQ_" + connection_name + '_' + \
                                         str(tcp_conn_info[connection_name]["request_counter"])
                            events_dict[event_name]["ACK_num"] += 1
                            events_dict[event_name]["packets_involved"] += 1
                            events_dict[event_name]["bytes_involved"] += ip.len
                        elif len(tcp_conn_info[connection_name]["src_wait_ack"]) == 0 or \
                             tcp.ack > max(tcp_conn_info[connection_name]["src_wait_ack"]):
                            continue
                        else:
                            if trace:
                                print "Retransmit HTTP request ACK", tcp.ack
                            event_name = "OBJREQ_" + connection_name + '_' + \
                                         str(tcp_conn_info[connection_name]["request_counter"])
                            events_dict[event_name]["loss_packets"] += 1
                            events_dict[event_name]["packets_involved"] += 1

                #
                else:
                    if trace:
                        print "Error: unknown HTTP packet"
                    continue
            else:
                if trace:
                    print "Error: unknown TCP status"
                continue

        if ip.p == dpkt.ip.IP_PROTO_UDP:
            
            udp = ip.data

            # ensure this is DNS packet
            if udp.sport != 53 and udp.dport != 53:
                continue
            dns = dpkt.dns.DNS(udp.data)
            if dns.qr == dpkt.dns.DNS_Q:  # DNS query packet
                if dns.opcode != dpkt.dns.DNS_QUERY:
                    if trace:
                        print "Error: no DNS_QUERY, opcode: ", dns.opcode
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

                if my_ip == "":
                    set_my_ip(socket.inet_ntoa(ip.src))

                if trace:
                    print dns.id, "DNS query:", dns.qd[0].name
                
                events_dict["DNS_" + str(dns.id)] = {"src": src_ip, "dst": dst_ip,
                                                     "start_ts": ts, "end_ts": 0,
                                                     "bytes_involved": ip.len, "packets_involved": 1,
                                                     "ACK_num": 0, "loss_packets": 0}
                dns_query_counter += 1
            else: # DNS reply packet
                if dns.opcode != dpkt.dns.DNS_QUERY:
                    print "Error: no DNS_QUERY, opcode: ", dns.opcode
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
                        if trace:
                            print dns.id, "CNAME request", answer.name, "\tresponse", answer.cname
                    elif answer.type == dpkt.dns.DNS_A:
                        ip_addr = socket.inet_ntoa(answer.rdata)
                        dst_ip_set.add(ip_addr)
                        if trace:
                            print dns.id, "A request", answer.name, "\tresponse", ip_addr
                    elif answer.type == dpkt.dns.DNS_PTR:
                        pass#print dns.id, "PTR request", answer.name, "\tresponse", answer.ptrname
                event_name = "DNS_" + str(dns.id)
                events_dict[event_name]["end_ts"] = ts
                events_dict[event_name]["bytes_involved"] += ip.len
                events_dict[event_name]["packets_involved"] += 1

    if trace:
        print "Total number of packets in the pcap file: ", counter
        print "**************"

    for event_name, event_record in events_dict.iteritems():
        if event_name[:3] == "DNS":
            print '<DNS request, %s, %s, %s, %s, %d, %d, %d, %d>' % (
                    event_record["src"], event_record["dst"], 
                    event_record["start_ts"], event_record["end_ts"],
                    event_record["bytes_involved"], event_record["packets_involved"],
                    event_record["ACK_num"], event_record["loss_packets"])
        elif event_name[:7] == "TCPCONN":
            print '<%s, %s, %s, %s, %s, %d, %d, %d, %d>' % (event_name,
                    event_record["src"], event_record["dst"], 
                    event_record["start_ts"], event_record["end_ts"],
                    event_record["bytes_involved"], event_record["packets_involved"],
                    event_record["ACK_num"], event_record["loss_packets"])
        elif event_name[:6] == "OBJREQ":
            print '<%s, %s, %s, %s, %s, %d, %d, %d, %d>' % (event_name,
                    event_record["src"], event_record["dst"], 
                    event_record["start_ts"], event_record["end_ts"],
                    event_record["bytes_involved"], event_record["packets_involved"],
                    event_record["ACK_num"], event_record["loss_packets"])
            # print "downloading object cost", event_record["end_ts"] - event_record["start_ts"]

if __name__ == "__main__":
    # pcap_filename = '../wired_firefox/wired_firefox_amazon.com_1329408462.02.pcap'
    # pcap_filename = '../wired_android/wired_android_amazon.com_1329408440.26.pcap'
    pcap_filename = '../t-mobile_android/t-mobile_android_aol.com_1329414398.57.pcap'
    parse(pcap_filename)
#!/usr/local/bin/python2.7

import sys
import os

import pcap_parser

scenario_dirs = ['t-mobile_android', 't-mobile_firefox', 'verizon_firefox', 'wired_android', 'wired_firefox']
websites = ['amazon.com', 'cnn.com', 'microsoft.com', 'twitter.com', 'adobe.com', 'taobao.com']
pcaps_dir = '../pcaps/'

for website in websites:
	print "---------%s----------" % website
	print "Scenario                 DNS_time   TCP_conn_time   object_time   total_time" \
		  "  loss_packets  rtt_num   TCP_num     object_num     site_num avg_obj_download_rate"

	for scenario in scenario_dirs:
		file_dir = pcaps_dir + scenario
		file_list = os.listdir(file_dir)
		file_name = ""
		for file in file_list:
			if website in file:
				file_name = file
				break
		if file_name == "":
			print "No %s pcap file in scenario %s" % (website, scenario)
			continue

		file_name = pcaps_dir + scenario + '/' + file_name
		# print file_name
		events = pcap_parser.parse(file_name)

		dns_count = 0
		dns_time = 0.0
		tcp_conn_count = 0
		tcp_conn_time = 0.0
		object_request_count = 0
		object_request_time = 0.0
		total_object_len = 0
		total_loss_packet = 0
		total_rtt = 0
		min_ts = sys.float_info.max
		max_ts = sys.float_info.min
		site_set = set()

		for event, record in events.iteritems():
			min_ts = min(min_ts, record["start_ts"])

			cost_time = float(record["end_ts"]) - float(record["start_ts"])
			if record["end_ts"] == 0:
				cost_time = 0
			else:
				max_ts = max(max_ts, record["end_ts"])

			if event[:3] == "DNS":
				dns_count += 1
				dns_time += cost_time

			elif event[:7] == "TCPCONN":
				tcp_conn_count += 1
				tcp_conn_time += cost_time
			elif event[:6] == "OBJREQ":
				object_request_count += 1
				object_request_time += cost_time
				site_set.add(record["dst"])
				total_object_len += record["bytes_involved"]

			# print record["loss_packets"]
			total_loss_packet += record["loss_packets"]
			total_rtt += record["ACK_num"]

		total_time = max_ts - min_ts

		print "%18s   %10.4f   %10.4f   %10.4f   %10.4f   %10d   %10d   %10d   %10d   %10d   %10.4f" % (
				scenario, dns_time/dns_count, tcp_conn_time, object_request_time, total_time,
				total_loss_packet, total_rtt, object_request_count, tcp_conn_count,
				len(site_set), total_object_len / object_request_time)

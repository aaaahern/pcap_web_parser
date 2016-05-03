# pcap_web_parser

## Background
A web download session starts with a primary page download followed by downloads of a lot of different objects which make the entire page. A web session can roughly be divided into the following stages in a simplified setup:

a. Initial DNS request and response
b. Main page download
c. Parallel DNS requests to several new domains from which objects need to be downloaded. For example, you may request, http://www.microsoft.com, but to download the page, there might be an object in a completely different domain. All such domains need to be resolved.
d. Setup of parallel connections to different sites.
e. Across each connection to a particular site, the client browser will download multiple objects. For example, a website might contain 100 objects which need to be downloaded from 1 site and might have 4 parallel connections. Each connection might roughly download 25 objects. Each object might have a different size which will influence the completion times. One can determine the start of a new object by the start of a GET request in the pcap file.
f. One might repeat steps c,d,e multiple times. For example, if a downloaded object is a javascript file, it can issue new requests to new domains.
g. Finally when all the objects are done, there is a finish stage.

## Parser Introduction

This parser is used to parse the pcap file which contains all packets in a web download session, produce and analyze events of web download session. 

Event information structure:
> Type of event, src host, dst host, start time, end time, bytes involved, packets involved, number of RTTs of interaction, number of packet loss events in the event

There are three kinds of events:

1. DNS query
2. TCP connection establishment 
3. Object request on established connection

Example output:
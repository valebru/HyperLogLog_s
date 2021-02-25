#!/usr/bin/env python2.7

import numbers
from operator import itemgetter 
import math
import xxhash
import socket
import sys
import numpy
from scipy import stats
import dpkt
import time
import argparse
from datetime import datetime

MIN_RANK = 5

VERBOSE_ITEM = "1112.238.162.249" 

def hll_rank(hash0, bits):
    i=0
    for i in range(1,32-bits):
        if hash0 & 1:
            break
        hash0 = hash0 >> 1

    return i


#================= MAIN

if __name__ == '__main__':

    # Instantiate the parser
    parser = argparse.ArgumentParser(description='PCAP exact counting') 

    # Positional argument
    parser.add_argument('pcap', type=str, help='pcap file')

    # Positional argument
    parser.add_argument('out', type=str, help='out file')

    # Optional argument
    parser.add_argument('--min_rank', type=int, help='')

    # Optional argument
    parser.add_argument('--parsing_mode', type=int, help='')

    print('command line: ' + ' '.join(sys.argv))
    args = parser.parse_args()
    start = datetime.now()

    if args.min_rank: MIN_RANK = args.min_rank
    # function mode (<flow key , discriminator key>) 
    # 1 <src_ip , dst_ip> 
    # 2 <dst_ip , src_ip> 
    # 3 <src_ip , 5-tuple> 
    # 4 <dst_ip , 5-tuple> 
    parsing_mode=4
    if args.parsing_mode: parsing_mode = args.parsing_mode


try:
    f1 = args.pcap
    f2 = args.out 

    fr1 = open(f1, 'rb')
    fr2 = open(f2, 'w')
except IndexError:
    print("Error: no Filename - <pcap_trace> <output_stat_file>")
    sys.exit(2)



pcap=dpkt.pcap.Reader(fr1)

#----
element={}
gelement={}
debug_info={}
debug_info['pkt']=0
tot_pkts=0

for ts, buf in pcap:
    verbose=False
    try:
        if pcap.datalink() == dpkt.pcap.DLT_LINUX_SLL:
            eth = dpkt.sll.SLL(raw_pkt)
        else:
            eth = dpkt.ethernet.Ethernet(buf)
    except NotImplementedError:
        verbose=True
        print("Not Implemented for pkt: " + str(tot_pkts))

    #eth=dpkt.ethernet.Ethernet(buf)
    if eth.type != dpkt.ethernet.ETH_TYPE_IP:
        continue
    ip = eth.data
    sport=0
    dport=0

   #Packet Parsing
    src =socket.inet_ntop(socket.AF_INET, ip.src)
    dst =socket.inet_ntop(socket.AF_INET, ip.dst)

    try:
        if (ip.p == dpkt.ip.IP_PROTO_TCP) and (len(ip) >24):
            tcp = ip.data
            sport = tcp.sport
            dport = tcp.dport
        elif (ip.p == dpkt.ip.IP_PROTO_UDP) and (len(ip) > 24):
            udp = ip.data
            sport = udp.sport
            dport = udp.dport
        else:
            sport = 0
            dport = 0

    except AttributeError:
        verbose=False
       #verbose=True
       #print(src, dst, ip.p, len(ip), len(ip.data), len(eth))

    # function mode (<flow key , discriminator key>) 
    # 1 <src_ip , dst_ip> 
    # 2 <dst_ip , src_ip> 
    # 3 <src_ip , 5-tuple> 
    # 4 <dst_ip , 5-tuple> 
    if( parsing_mode == 2):
        topk_key = dst
        hll_item = src + " " + dst 
    elif( parsing_mode == 3):
        topk_key = src
        hll_item = src + " " + dst + " " + str(sport) + " " + str(dport)
    elif( parsing_mode == 4):
        topk_key = dst
        hll_item = src + " " + dst + " " + str(sport) + " " + str(dport)
    else:
        topk_key = src
        hll_item = src + " " + dst 

    if verbose:
        print(hll_item)

    tot_pkts = tot_pkts + 1
    debug_info['pkt'] = debug_info['pkt'] + 1

    #Exact counting
    try:
        element[topk_key][hll_item] = 1
        element[topk_key]["pkt_count"] = element[topk_key]["pkt_count"] + 1
    except KeyError:
        element[topk_key] = {}
        element[topk_key][hll_item] = 1
        element[topk_key]["pkt_count"] = 1
        element[topk_key]["rank_count"] = 0

    #Gloobal counting
    gelement[hll_item] = 1

    hash0 = xxhash.xxh32(hll_item.encode('ascii')).intdigest() 
    rank0 = hll_rank(hash0, 0);
    if rank0 > MIN_RANK:
        element[topk_key]["rank_count"] = element[topk_key]["rank_count"] + 1

fr1.close

print("============= end parsing phase =============")
now = datetime.now()

print("Global HLL:", len(gelement), len(element))
fr2.write('command line: ' + ' '.join(sys.argv) + '\n')
fr2.write('simulation time: ' + str(now-start) + '\n')
fr2.write("==========================================\n")
fr2.write("Global HLL: " + str(len(gelement)) + " " +  str(len(element)) + "\n")

#Reference statistics, exact counting
ref_list={}
tot_cardinality=0
for ref_key in element:
    ref_list[ref_key]=len(element[ref_key].keys())-2
    tot_cardinality = tot_cardinality + ref_list[ref_key]

#Saving exact_counting
fr2.write("cardinality_count" + "\t" + "key" + "\t" + "ratio_cardinality" + "\t\t||\t" + "elephant_count" + "\t" + "ratio_elephant" + "\t|\t" + "overMinRank" + "\t" + "ratio_overMinRank" + "\n")
fr2.write("==========VVV=============\n")
for item in element:
    fr2.write(str(ref_list[item]) +" \t " + item + " \t " + str(format(float(ref_list[item]*100/(tot_cardinality+0.0)),'.3g')) + "\t\t||\t" + str(element[item]["pkt_count"]) + " \t " + str(format(float(element[item]["pkt_count"]*100/(tot_pkts+0.0)),'.3g'))  + "\t|\t" +  str(element[item]["rank_count"])  +" \t " + str(format(float(element[item]["rank_count"]*100/(element[item]["pkt_count"]+0.0)),'.3g'))  + "\n")
fr2.write("==========V=============\n")
fr2.close

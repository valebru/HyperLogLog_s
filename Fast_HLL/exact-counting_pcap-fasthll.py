#!/usr/bin/env python2.7

import numbers
from operator import itemgetter 
import math
import xxhash_cffi as xxhash
import socket
import numpy as np
import sys
import numpy
from scipy import stats
import dpkt
import time
import argparse
from datetime import datetime


VERBOSE_ITEM = "1112.238.162.249" 

def hll_rank(hash0, bits):
    i=0
    for i in range(1, 64-bits):
        if hash0 & 1:
            break
        hash0 = hash0 >> 1

    return i

def hll_rawc(hll_reg, hll_bits, hll_size):
    rawc = 0
    
    for item in hll_reg:
        rawc = rawc + (1 << item)

    return rawc

def hll_regc(hll_reg, hll_bits, hll_size):
    regc = 0
    
    for item in hll_reg:
        regc = regc + (item != 0)

    return regc


def hll_estimation(hll_reg, hll_bits, hll_size):
    alpha_mm=0
    i=0

    if hll_bits == 4:
        alpha_mm = 0.673
    elif hll_bits == 5:
        alpha_mm = 0.697
    elif hll_bits == 6:
        alpha_mm = 0.709
    else:
        alpha_mm = 0.7213 / (1.0 + 1.079 /hll_size)

    alpha_mm = alpha_mm * (float(hll_size) * float(hll_size));

    isum = 0
    for item in hll_reg:
        isum = isum +1.0 / (1 << item)

    estimate = alpha_mm / isum;

    if estimate <= 5.0 / 2.0 * float(hll_size):
        zeros = 0

        for item in hll_reg:
            zeros = zeros + (item == 0)


        if zeros:
            estimate = float(hll_size) * math.log(float(hll_size) / zeros)

    elif estimate > (1.0 / 30.0) * 4294967296.0:
        estimate = -4294967296.0 * math.log(1.0 - (estimate / 4294967296.0))


    return estimate;






#================= MAIN

if __name__ == '__main__':

    # Instantiate the parser
    parser = argparse.ArgumentParser(description='Top-k HLL simulator') 

    # Positional argument
    parser.add_argument('pcap', type=str, help='pcap file')

    # Positional argument
    parser.add_argument('exact_out', type=str, help='exact_out file')

    # Optional argument
    parser.add_argument('--hll_bits', type=int, help='')


    # Optional argument
    parser.add_argument('--parsing_mode', type=int, help='')

    print('command line: ' + ' '.join(sys.argv))
    args = parser.parse_args()
    start = datetime.now()

try:
    #print("file1: \t" + str(sys.argv[1]))

    f1 = args.pcap
    f2 = args.exact_out 

	
    if  args.hll_bits: hll_bits =  args.hll_bits
    else: hll_bits = 8

    hll_size = 1 << hll_bits

    # function mode (<flow key , discriminator key>) 
    # 1 <src_ip> 
    # 2 <dst_ip> 
    # 3 <src_ip, dst_ip> 
    # 4 <5-tuple> 
    parsing_mode=4
    if args.parsing_mode: parsing_mode = args.parsing_mode

    #fr1 = open(f1, 'rb')
    fr1 = open(f1, 'r')
    fr2 = open(f2, 'a')
except IndexError:
    print("Error: no Filename - <pcap_trace> <output_stat_file>")
    sys.exit(2)


print(hll_bits, hll_size)


pcap=dpkt.pcap.Reader(fr1)


#----HLL_INIT
hll_reg0=[0]*hll_size
hll_reg1=[0]*hll_size
#----
element={}

debug_info={}
debug_info['pkt_parsing']=0
debug_info['hash_comp']=0
debug_info['pkt']=0

debug_hll0={}
debug_hll0['rank_ver']=0
debug_hll0['hll_up']=0
debug_hll0['min_comp']=0
debug_hll0['min_swap']=0
debug_hll0['min_value']=0
debug_hll0['reg_g_min']=0

debug_hll1={}
debug_hll1['rank_ver']=0
debug_hll1['hll_up']=0
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
        hll_item = dst 
    elif( parsing_mode == 3):
        hll_item = src + " " + dst 
    elif( parsing_mode == 4):
        hll_item = src + " " + dst + " " + str(sport) + " " + str(dport)
    else:
        hll_item = src  

    if verbose:
        print(hll_item)

    tot_pkts = tot_pkts + 1
    debug_info['pkt'] = debug_info['pkt'] + 1
    debug_info['pkt_parsing'] = debug_info['pkt_parsing'] + 1

    #Exact counting
    try:
        element[hll_item] = element[hll_item] + 1
    except KeyError:
        element[hll_item] = 1


    #HLL evaluation
    hash0 = xxhash.xxh64(hll_item.encode('ascii')).intdigest() 
    index0 = hash0 >> (64 - hll_bits)
    rank0 = hll_rank(hash0, hll_bits);
    debug_info['hash_comp'] = debug_info['hash_comp'] + 1

    #Regular HLL
    old_rank1 = hll_reg1[index0]
    debug_hll1['rank_ver'] = debug_hll1['rank_ver'] + 1
    if rank0 > old_rank1:
        debug_hll1['hll_up'] = debug_hll1['hll_up'] + 1
        hll_reg1[index0] = rank0

    #Fast HLL
    if not rank0 < debug_hll0['min_value'] + 1:
    #HLL updating 
        debug_hll0['rank_ver'] = debug_hll0['rank_ver'] + 1
        old_rank0 = hll_reg0[index0]
        if rank0 > old_rank0:
            debug_hll0['hll_up'] = debug_hll0['hll_up'] + 1
            hll_reg0[index0] = rank0

            if old_rank0 == debug_hll0['min_value']:
                debug_hll0['reg_g_min'] = debug_hll0['reg_g_min'] + 1
                debug_hll0['min_comp'] = debug_hll0['min_comp'] + 1
            
                if not debug_hll0['reg_g_min'] < hll_size:
                    debug_hll0['min_swap'] = debug_hll0['min_swap'] + 1
                    debug_hll0['min_value'] = min(hll_reg0)
                    debug_hll0['reg_g_min'] = len([x for x in hll_reg0 if x > debug_hll0['min_value']])

fr1.close

print("============= end parsing phase =============")
now = datetime.now()

fr2.write('command line: ' + ' '.join(sys.argv) + '\n')
fr2.write('simulation time: ' + str(now-start) + '\n')
fr2.write("==========================================\n")
fr2.write("HLL: " + str(hll_bits) +  " " + str(hll_size) + "\n")

#Hll statistics
hll_info0={}
hll_info0["estimation"] = hll_estimation(hll_reg0, hll_bits, hll_size)
hll_info0["max_hll"]=max(hll_reg0)
hll_info0["min_hll"]=min(hll_reg0)

hll_info1={}
hll_info1["estimation"] = hll_estimation(hll_reg1, hll_bits, hll_size)
hll_info1["max_hll"]=max(hll_reg1)
hll_info1["min_hll"]=min(hll_reg1)

#Reference statistics, exact counting
ref_info={}
ref_info["cardinality_count"] = len(element.keys())
ref_info["elephant_count"] = debug_info['pkt']
ref_info["maximum_item_ripetion"] = max(element.values())
ref_info["average_item_ripetion"] = np.mean(element.values())


#Saving results 
fr2.write("------------------------------------------\n")
#fr2.write(str(abs(hll_info1["estimation"] - ref_info["cardinality_count"])*100/ref_info["cardinality_count"]) + "\t" + str(abs(hll_info1["estimation"] - hll_info0["estimation"])*100/hll_info1["estimation"]) + "\t|\t" + str(float(abs(debug_hll0['rank_ver'])*100)/(debug_hll1['rank_ver']+0.0))+  "\t" +  str(debug_hll0['min_comp']) + "\t" + str(debug_hll0['min_swap'])  +"\n")
fr2.write("==========VVV=============\n")
fr2.write(str(ref_info)+ "\n")
fr2.write(str(debug_hll0)+ "\n")
fr2.write(str(hll_info0)+ "\n")
fr2.write(str(debug_hll1)+ "\n")
fr2.write(str(hll_info1)+ "\n")
fr2.write("==========V=============\n")
fr2.close

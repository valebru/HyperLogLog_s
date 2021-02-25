#!/usr/bin/env python2.7

from multiprocessing import Process
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
import os

MIN_RANK = 5

VERBOSE_ITEM = "1112.238.162.249" 

def hll_rank(hash0, bits):
    i=0
    for i in range(1, 64-bits):
        if hash0 & 1:
            break
        hash0 = hash0 >> 1

    return i



# Define a function for the thread
def sim_run( threadName, seed, hll_bits, grouped_hll, num_bits, filenames):
    parsing_mode = 4
    start = datetime.now()
    np.random.seed(seed)
    try:
        f2 = threadName+"_"+str(hll_bits)+"-"+str(grouped_hll)+"_"+str(num_bits)+".txt" 
        fr2 = open(f2, 'w')
        f3 = threadName+"_timing.txt" 
        fr3 = open(f3, 'a')
    except IndexError:
        print("Error: Filename ")
        sys.exit(2)

    hll_st_list=[]
    hll_st1_list=[]
    hll_st2_list=[]
    gelement_list=[]
    abs_err_list=[]
    abs_err1_list=[]
    abs_err2_list=[]

    hll_size = 1 << hll_bits

    runs = 0
    for filename in filenames:
        runs = runs + 1
        xseed = seed + (12+runs)*runs
        try:
            fr1 = open(filename, 'r')
        except IndexError:
            print("Error: Filename ")
            sys.exit(2)
        print(threadName,filename,runs,hll_bits,grouped_hll,num_bits)

        pcap=dpkt.pcap.Reader(fr1)

        #----HLL streaming INIT
        hll_reg0=[0]*hll_size
        q_st = float(hll_size) 
        hll_st = 0
        #----Debug
        gelement={}
        debug_info={}
        debug_info['pkt']=0
        tot_pkts=0
        #----HLL grouped streaming INIT
        mask_bits=(1<<num_bits)-1
        num_reg=hll_size/grouped_hll
        hll_reg2=[num_bits]*num_reg
        #hll_reg2=[0]*num_reg
        hll_vec2={}
        for i in range(0,num_reg):
            hll_vec2[i]=[0]*grouped_hll
        hll_st2 = 0
        hll_st1 = 0
        #----

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

            tot_pkts = tot_pkts + 1
            debug_info['pkt'] = debug_info['pkt'] + 1

            #Exact counting
            #Gloobal counting
            gelement[hll_item] = 1



            #HLL streaming
            hash0 = xxhash.xxh64(hll_item.encode('ascii'), seed=xseed).intdigest() 
            #-----HLL_ADDING_PHASE
            index0 = hash0 >> (64 - hll_bits)
            rank0 = hll_rank(hash0, hll_bits);

            if rank0 > hll_reg0[index0]:
                #streaming update
                hll_st += float(hll_size)/q_st
                q_st += 1.0/(1<<rank0) -1.0/(1<<hll_reg0[index0])

                # reg update
                hll_reg0[index0] = rank0

            #HLL grouped streaming
            #hash2 = xxhash.xxh64(hll_item.encode('ascii')).intdigest() 
            hash2 = hash0 
            #-----HLL_ADDING_PHASE
            index2 = hash2 >> (64 - hll_bits)
            reg_index = index2 / grouped_hll
            vec_index = index2 % grouped_hll
            rank2 = hll_rank(hash2, hll_bits);


            #print(q_st2, hll_st2, rank2, reg_index,vec_index, hll_vec2[reg_index], hll_reg2[reg_index])
            if rank2 > hll_reg2[reg_index]:
                #streaming prob to modify sketch
                q_st2 = 0
                for i in range(0,num_reg):
                    q_st2 += 4.0/ (1 << (hll_reg2[i]))
                    for j in range(0,grouped_hll):
                        for k in range(0,num_bits):
                            q_st2 += (((~hll_vec2[i][j] >> k) & 1)+0.0) /(1 << (hll_reg2[i]-num_bits+1+k))

                # reg update
                shift = rank2 - hll_reg2[reg_index]
                hll_reg2[reg_index] = rank2
                for j in range(0,grouped_hll):
                    hll_vec2[reg_index][j] = (hll_vec2[reg_index][j] >> shift) & mask_bits
                hll_vec2[reg_index][vec_index] |= (1 << (num_bits-1)) & mask_bits
                hll_st2 += float(hll_size)/q_st2
            elif hll_reg2[reg_index] - rank2 < num_bits:
                if ((hll_vec2[reg_index][vec_index] >> (num_bits -1 - hll_reg2[reg_index] + rank2)) & 1)==0:
                    #streaming prob to modify sketch
                    q_st2 = 0
                    for i in range(0,num_reg):
                        q_st2 += 4.0/ (1 << (hll_reg2[i]))
                        for j in range(0,grouped_hll):
                            for k in range(0,num_bits):
                                q_st2 += (((~hll_vec2[i][j] >> k) & 1)+0.0)/(1 << (hll_reg2[i]-num_bits+1+k))

                    #vec update
                    hll_st2 += float(hll_size)/q_st2
                    hll_vec2[reg_index][vec_index] |= (1 << (num_bits -1 - hll_reg2[reg_index] + rank2)) & mask_bits
            #print(q_st2, hll_st2, rank2, reg_index,vec_index, hll_vec2[reg_index], hll_reg2[reg_index])


        #streaming prob to modify sketch - estimation at the end of the data stream
        q_st2 = 0
        for i in range(0,num_reg):
            q_st2 += 4.0/ (1 << (hll_reg2[i]))
            for j in range(0,grouped_hll):
                for k in range(0,num_bits):
                    q_st2 += (((~hll_vec2[i][j] >> k) & 1)+0.0)/(1 << (hll_reg2[i]-num_bits+1+k))
        hll_st1 = q_st2/float(hll_size)

        fr2.write(str(runs) + "\t" + str(round(hll_st,3)) +"\t"+ str(round(q_st/float(hll_size),6))     +"\t"+ str(round(hll_st2,3)) +"\t"+ str(round(hll_st1,6)) +"\t"+ str(len(gelement)) + "\t" + str(tot_pkts) + "\t" + filename + "\n")
        print(threadName, runs, hll_st, q_st/float(hll_size), hll_st2, hll_st1, len(gelement), tot_pkts, filename)
        hll_st_list.append(hll_st)
        hll_st1_list.append(hll_st1)
        hll_st2_list.append(hll_st2)
        gelement_list.append(len(gelement))
        abs_err_list.append(abs(hll_st - len(gelement)))
        abs_err1_list.append(abs(hll_st1 - len(gelement)))
        abs_err2_list.append(abs(hll_st2 - len(gelement)))




    fr3.write("------------------------------------------\n")
    now = datetime.now()
    fr3.write(threadName+'-command line: ' + ' '.join(sys.argv) + '\n')
    fr3.write('simulation time: ' + str(now-start) + '\n')
    fr3.write("==========================================\n")
    fr3.write(str(np.mean(hll_st_list)) +" "+ str(np.mean(hll_st2_list)) +" "+ str(np.mean(gelement_list)) + " - " + str(np.mean(abs_err_list)) + " " + str(np.mean(abs_err2_list))  +"\n")
    fr3.write(str(np.std(hll_st_list)) +" "+ str(np.std(hll_st2_list)) +" "+ str(np.std(gelement_list)) + " - " + str(np.std(abs_err_list)) + " " + str(np.std(abs_err2_list))  +"\n")

    fr2.close()
    fr3.close()


#================= MAIN

if __name__ == '__main__':

    # Instantiate the parser
    parser = argparse.ArgumentParser(description='PCAP exact counting') 
    # Positional argument
    parser.add_argument('file_list', type=str, help='file_list')

    # Optional argument
    parser.add_argument('--hll_bits', type=int, help='')


    # Optional argument
    parser.add_argument('--parsing_mode', type=int, help='')

    print('command line: ' + ' '.join(sys.argv))
    args = parser.parse_args()
    start = datetime.now()

try:
    #print("file1: \t" + str(sys.argv[1]))

    f1 = args.file_list

	
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
except IndexError:
    print("Error: no Filename - <pcap_trace> <output_stat_file>")
    sys.exit(2)


ths = []
grouped_hll=4
num_bits=4
print( hll_bits, hll_size)

filenames = []

for line in fr1:
    line = line.replace('\n','')
    filenames.append(line)

print(filenames)
ths = []
#for hll_bits in [8, 10, 12, 14]:
for hll_bits in [10]:
    for grouped_hll in [2, 4, 8]:
        for num_bits in [3, 4, 5, 6]:
            ths.append( Process(target = sim_run, args = ("Trace", 192, hll_bits, grouped_hll, num_bits, filenames) ) )

            if len(ths) > 18:
                # Wait for all threads to complete
                for t in ths:
                    t.start()
                    print(t)
                    time.sleep(8)
                print "End starting threadings"

                for t in ths:
                    t.join()
                    time.sleep(8)
                print "End main thread"
                ths = []



# Wait for all threads to complete
for t in ths:
    t.start()
    print(t)
    time.sleep(8)
print "End starting threadings"

for t in ths:
    t.join()
    time.sleep(8)
print "End main thread"


#os.system("taskset -p -c 0,2,4 %d" % os.getpid())



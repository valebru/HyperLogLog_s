import numpy as np
import numbers
import math
import xxhash_cffi as xxhash
import socket
import sys
import numpy
from scipy import stats
import dpkt


def hll_rank(hash0, bits):
    i=0
    for i in range(1,32-bits):
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



def hll_linestimation(hll_reg, hll_bits, hll_size):
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

    zeros = 0

    for item in hll_reg:
        zeros = zeros + (item == 0)


    if zeros:
        estimate = float(hll_size) * math.log(float(hll_size) / zeros)



    return estimate;


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
#
#    if estimate <= 5.0 / 2.0 * float(hll_size):
#        zeros = 0
#
#        for item in hll_reg:
#            zeros = zeros + (item == 0)
#
#
#        if zeros:
#            estimate = float(hll_size) * math.log(float(hll_size) / zeros)
#
#    elif estimate > (1.0 / 30.0) * 4294967296.0:
#        estimate = -4294967296.0 * math.log(1.0 - (estimate / 4294967296.0))
#
#
    return estimate;


def hll_estimationST(hll_reg, hll_bits, hll_size):
    alpha_mm=0
    i=0

#    if hll_bits == 4:
#        alpha_mm = 0.673
#    elif hll_bits == 5:
#        alpha_mm = 0.697
#    elif hll_bits == 6:
#        alpha_mm = 0.709
#    else:
#        alpha_mm = 0.7213 / (1.0 + 1.079 /hll_size)
    alpha_mm = 0.7213 / (1.0 + 1.079 /hll_size)

    isum = 0
    for item in hll_reg:
        isum = isum +1.0 / (1 << item)

    estimate = alpha_mm / isum;

    return estimate;


try:
    #print("file1: \t" + str(sys.argv[1]))

    f1 = str(sys.argv[1])
    f2 = str(sys.argv[2])
    filenameref = str(sys.argv[3])
    hll_bits= int(sys.argv[4])

    fr1 = open(f1, 'rb')
    fr2 = open(f2, 'w')
    fref = open(filenameref, 'r')
except IndexError:
    print("Error: no Filename")
    sys.exit(2)

#----HLL_INIT
#REF_file inspection
ref_value = {}
inside=False
for line in fref:
    if (not line.find("==========V=============") and inside):
        inside=False

    if inside:
        tmp = line.split()
        ref_value[tmp[1]] = float(tmp[0])

    if (not line.find("==========VVV=============") and not inside):
        inside=True

ref_k_value = sorted(ref_value, key=ref_value.get, reverse=True)[0:100]

hll_list={}
q_st={}
hll_st={}
#hll_bits=0
hll_size=1<<hll_bits
for item in ref_k_value:
    hll_list[item] = [0]*hll_size
    q_st[item] = float(hll_size) 
    hll_st[item] = 0


#print(hll_bits, hll_size)
#print(ref_k_value)
#print(hll_list)



pcap=dpkt.pcap.Reader(fr1)


element={}
tot_pkts=0
for ts, buf in pcap:
    verbose=False
    try:
        if pcap.datalink() == dpkt.pcap.DLT_LINUX_SLL:
            eth = dpkt.sll.SLL(raw_pkt)
        else:
            eth = dpkt.ethernet.Ethernet(buf)
    except NotImplementedError:
        verbose=False
        #print("Not Implemented for pkt: " + str(tot_pkts))

    #eth=dpkt.ethernet.Ethernet(buf)
    if eth.type != dpkt.ethernet.ETH_TYPE_IP:
        continue
    ip = eth.data
    tot_pkts = tot_pkts + 1
    sport=0
    dport=0

    src =socket.inet_ntop(socket.AF_INET, ip.src)
    dst =socket.inet_ntop(socket.AF_INET, ip.dst)



    try:
        if ip.p == dpkt.ip.IP_PROTO_TCP and len(ip) >24:
            tcp = ip.data
            sport = tcp.sport
            dport = tcp.dport
        elif ip.p == dpkt.ip.IP_PROTO_UDP and len(ip) > 24:
            udp = ip.data
            sport = udp.sport
            dport = udp.dport
        else:
            sport = 0
            dport = 0

    except AttributeError:
        verbose=True
        #print(src, dst, ip.p, len(ip), len(ip.data), len(eth))

    item = src + " " + dst + " " + str(sport) + " " + str(dport)

    #if verbose:
    #    print(item)

    if dst in ref_k_value:
        try:
            element[dst][item] = 1
            element[dst]["count"] = element[dst]["count"] + 1
        except KeyError:
            element[dst] = {}
            element[dst]["count"] = 1

        hll_reg0 = hll_list[dst]
        hash0 = xxhash.xxh32(item.encode('ascii')).intdigest() 
        #-----HLL_ADDING_PHASE
        index0 = hash0 >> (32 - hll_bits)
        rank0 = hll_rank(hash0, hll_bits);

        

        if rank0 > hll_reg0[index0]:
            #streaming update
            hll_st[dst] += float(hll_size)/q_st[dst] 
            q_st[dst] += 1.0/(1<<rank0) -1.0/(1<<hll_reg0[index0])

            # reg update
            hll_reg0[index0] = rank0

fr1.close

print("end parsing phase")
#print(hll_list)

hll_count={}
hll_lcount={}
hll_rawcount = {}
hll_regcount = {}
for srckey in ref_k_value:
    hll_count[srckey] = hll_estimation(hll_list[srckey], hll_bits, hll_size)
    hll_lcount[srckey] = hll_linestimation(hll_list[srckey], hll_bits, hll_size)
    hll_rawcount[srckey] = hll_rawc(hll_list[srckey], hll_bits, hll_size)
    hll_regcount[srckey] = hll_regc(hll_list[srckey], hll_bits, hll_size)


hll_err=[]
hll_l_err=[]
hll_s_err=[]
for item in ref_k_value:
    hll_err.append(abs(  len(element[item].keys()) - hll_count[item])/ len(element[item].keys()))
    hll_l_err.append(abs(len(element[item].keys()) - hll_lcount[item])/len(element[item].keys()))
    hll_s_err.append(abs(len(element[item].keys()) - hll_st[item])/    len(element[item].keys()))
    fr2.write(str(len(element[item].keys())) +"\t" + item + "\t" + str(element[item]["count"]) + "\t||\t" + str(hll_count[item])  + "\t" + str(hll_lcount[item])  + "\t" + str(hll_rawcount[item])  + "\t" + str(hll_regcount[item])  + "\t" + str(max(hll_list[item])) + "\t||\t" + str(hll_st[item]) + "\t||\t" + str(abs(len(element[item].keys())-hll_count[item])) + "\t" + str(abs(len(element[item].keys())-hll_lcount[item])) + "\t" + str(abs(len(element[item].keys())-hll_st[item])) + "\n")
    #print(str(element[item]) +" " + item)
fr2.close

print(hll_bits, hll_size,"mean",np.mean(hll_err), np.mean(hll_l_err), np.mean(hll_s_err) , "std", np.std(hll_err), np.std(hll_l_err), np.std(hll_s_err) , f1)

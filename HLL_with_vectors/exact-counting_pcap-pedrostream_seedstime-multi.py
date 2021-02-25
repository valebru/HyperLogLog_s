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
import random
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
def sim_run( threadName, seed, cardinalities, r_thr, hll_bits, grouped_hll, num_bits):
    np.random.seed(seed)
    start = datetime.now()
    try:
        f2 = threadName+"_"+str(hll_bits)+"-"+str(grouped_hll)+"_"+str(num_bits)+".txt" 
        fr2 = open(f2, 'w')
        f3 = threadName+"_timing.txt" 
        fr3 = open(f3, 'a')
    except IndexError:
        print("Error: Filename ")
        sys.exit(2)

    timer_list=[]
    timer1_list=[]
    hll_st_list=[]
    hll_st1_list=[]
    hll_st2_list=[]
    gelement_list=[]
    abs_err_list=[]
    abs_err1_list=[]
    abs_err2_list=[]

    hll_size = 1 << hll_bits

    for car_thr in cardinalities:
        gelement={}
        hll_items=[]
        while len(gelement) < car_thr:
            #hll_item = str(np.random.randint(1, car_thr<<6,1))
            hll_item = str(np.random.zipf(1.0001, 1))
            gelement[hll_item] = 1
            hll_items.append(hll_item)

        for runs in range(0,r_thr):
            xseed = seed + (12+runs)*runs
            random.shuffle(hll_items)
            print(threadName,car_thr,runs,hll_bits,grouped_hll,num_bits)
            #----HLL streaming INIT
            hll_reg0=[0]*hll_size
            q_st = float(hll_size) 
            hll_st = 0
            timer0 = start - start
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
            timer1 = start - start
            #----

            #while len(gelement) < car_thr:
            for hll_item in hll_items:
                #hll_item = str(np.random.zipf(zipf_a, 1))
                #hll_item = str(np.random.randint(1, car_thr<<6,1))

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

                start_0 = datetime.now()
                if rank0 > hll_reg0[index0]:
                    #streaming update
                    #hll_st += float(hll_size)/q_st
                    #q_st += 1.0/(1<<rank0) -1.0/(1<<hll_reg0[index0])
                    q_st = 0
                    for i in range(0,hll_size):
                        q_st += 1.0/(1<<hll_reg0[i])
                    hll_st += float(hll_size)/q_st

                    # reg update
                    hll_reg0[index0] = rank0
                end_0 = datetime.now()
                timer0 += end_0 - start_0

                #HLL grouped streaming
                #hash2 = xxhash.xxh64(hll_item.encode('ascii')).intdigest() 
                hash2 = hash0 
                #-----HLL_ADDING_PHASE
                index2 = hash2 >> (64 - hll_bits)
                reg_index = index2 / grouped_hll
                vec_index = index2 % grouped_hll
                rank2 = hll_rank(hash2, hll_bits);


                start_1 = datetime.now()
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
                end_1 = datetime.now()
                timer1 += end_1 - start_1

            #streaming prob to modify sketch - estimation at the end of the data stream
            q_st2 = 0
            for i in range(0,num_reg):
                q_st2 += 4.0/ (1 << (hll_reg2[i]))
                for j in range(0,grouped_hll):
                    for k in range(0,num_bits):
                        q_st2 += (((~hll_vec2[i][j] >> k) & 1)+0.0)/(1 << (hll_reg2[i]-num_bits+1+k))
            hll_st1 = q_st2/float(hll_size)

            fr2.write(str(runs) + "\t" + str(round(hll_st,3)) +"\t"+ str(round(q_st/float(hll_size),6))     +"\t"+ str(round(hll_st2,3)) +"\t"+ str(round(hll_st1,6)) +"\t"+ str(len(gelement)) + "\t" + str(tot_pkts) + "\t" + str(timer0.total_seconds()) + "\t" + str(timer1.total_seconds()) + "\n")
            print(threadName, runs, hll_st, q_st/float(hll_size), hll_st2, hll_st1, len(gelement), tot_pkts, (timer0.total_seconds()), (timer1.total_seconds()))
            hll_st_list.append(hll_st)
            hll_st1_list.append(hll_st1)
            hll_st2_list.append(hll_st2)
            gelement_list.append(len(gelement))
            abs_err_list.append(abs(hll_st - len(gelement)))
            abs_err1_list.append(abs(hll_st1 - len(gelement)))
            abs_err2_list.append(abs(hll_st2 - len(gelement)))
            timer_list.append(timer0)
            timer1_list.append(timer1)




    fr3.write("------------------------------------------\n")
    now = datetime.now()
    fr3.write(threadName + '-command line: ' + ' '.join(sys.argv) + '\n')
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

    print('command line: ' + ' '.join(sys.argv))
    args = parser.parse_args()
    start = datetime.now()


cardinalities=[10000, 25000, 50000, 75000, 100000, 250000, 500000, 750000, 1000000, 2500000, 5000000]
cardinalities=[10000, 50000, 100000, 500000, 1000000, 5000000]
cardinalities=[75000, 100000, 250000, 500000, 750000, 1000000, 2500000]
cardinalities=[]
for item in [75000, 100000, 250000, 500000, 750000, 1000000, 2500000]:
    for runs in range(0,10):
        cardinalities.append(item)
hll_bits=10
grouped_hll=4
num_bits=4

#os.system("taskset -p -c 5-15 %d" % os.getpid())

#def sim_run( threadName, seed, cardinalities, r_thr, hll_bits, grouped_hll, num_bits):
ths = []
#for hll_bits in [8, 10, 12, 14]:
for hll_bits in [10]:
    for grouped_hll in [4]:
        for num_bits in [3, 4, 5]:
            ths.append( Process(target = sim_run, args = ("Unif1", 12,  cardinalities, 10, hll_bits, grouped_hll, num_bits) ) )
            ths.append( Process(target = sim_run, args = ("Unif2", 92,  cardinalities, 10, hll_bits, grouped_hll, num_bits) ) )
            ths.append( Process(target = sim_run, args = ("Unif3", 592, cardinalities, 10, hll_bits, grouped_hll, num_bits) ) )
            ths.append( Process(target = sim_run, args = ("Unif4", 332, cardinalities, 10, hll_bits, grouped_hll, num_bits) ) )
            ths.append( Process(target = sim_run, args = ("Unif5", 992, cardinalities, 10, hll_bits, grouped_hll, num_bits) ) )

            if len(ths) > 11:
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


for hll_bits in [10]:
    for grouped_hll in [8]:
        for num_bits in [4]:
            ths.append( Process(target = sim_run, args = ("Unif1", 12,  cardinalities, 10, hll_bits, grouped_hll, num_bits) ) )
            ths.append( Process(target = sim_run, args = ("Unif2", 92,  cardinalities, 10, hll_bits, grouped_hll, num_bits) ) )
            ths.append( Process(target = sim_run, args = ("Unif3", 592, cardinalities, 10, hll_bits, grouped_hll, num_bits) ) )
            ths.append( Process(target = sim_run, args = ("Unif4", 332, cardinalities, 10, hll_bits, grouped_hll, num_bits) ) )
            ths.append( Process(target = sim_run, args = ("Unif5", 992, cardinalities, 10, hll_bits, grouped_hll, num_bits) ) )

            if len(ths) > 11:
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



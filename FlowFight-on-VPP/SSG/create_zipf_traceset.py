import matplotlib.pyplot as plt
import numpy as np
from scipy import special
from random import randint
import sys

try:
        f1 = str(sys.argv[1])
        trace_size = int(sys.argv[2])
        zipf_a = float(sys.argv[3])
        fw1 = open(f1, 'w')


except IndexError:
        print("Error: no Filename")
        sys.exit(2)

sel_proto=[1, 17, 6]
base_srcip=2588775439
base_dstip=1218717001

k=0
for i in range(0, trace_size):
        k=k+1
        zipf_i = int(np.random.zipf(zipf_a, 1))

        srcip=base_srcip+zipf_i
        dstip=base_dstip+i
        srcport=randint(1,65535)
        dstport=randint(1,65535)
        proto=sel_proto[ k % 3 ]

        fw1.write(str(srcip) + '\t' + str(dstip) + '\t' +str(srcport) + '\t' +str(dstport) + '\t' +str(proto) + '\t' +str(512)+ '\t' +str(585) + '\n')


fw1.close


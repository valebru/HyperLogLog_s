#!/bin/bash
dt=$(date '+%d-%m_%H-%M');
dpdkfile=/home/valerio/vpp-bench/scripts/dpdk-conf.lua
tracefile=$FF_DIR/tools_res/capture.pcap


echo "\n\n=======================================================================\n"
echo "----------MoonGen packet generator"
echo "\n\n=======================================================================\n"
sudo ${MoonGen_dir}/build/MoonGen ${MGSCR}/replay-pcap-hll.lua --dpdk-config=${dpdkfile} 0 1 ${tracefile} ${tracefile} ${tracefile} -l
sleep 10

echo "\n\n=======================================================================\n"
filename="${EXP_RES}/Basetest_res_${dt}.txt"
echo "----------saving results: ${filename}"
echo "\n\n=======================================================================\n"
sudo -E $BINS/vppctl -s /run/vpp/cli.sock hll count > ${filename}

cat ${filename}

sleep 5
echo "\n\n=======================================================================\n"
echo "----------Comparing results with reference to extract precision"
echo "\n\n=======================================================================\n"
python2.7 $FF_DIR/tools_res/parser_hll.py ${filename} ${EXP_RES}/output.txt $FF_DIR/tools_res/capture_ref.txt


#sudo -E $BINS/vppctl -s /run/vpp/cli.sock 

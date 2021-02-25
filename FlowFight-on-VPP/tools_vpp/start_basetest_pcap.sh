#!/bin/bash
dt=$(date '+%d-%m_%H-%M');

echo "\n\n=======================================================================\n"
echo "----------VPP packet generator startup"
echo "\n\n=======================================================================\n"
#sudo -E $BINS/vppctl -s /run/vpp/cli.sock exec $FF_DIR/tools_vpp/vpp_script_2streams
sudo -E $BINS/vppctl -s /run/vpp/cli.sock exec $FF_DIR/tools_vpp/vpp_script_pcap
sleep 5

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

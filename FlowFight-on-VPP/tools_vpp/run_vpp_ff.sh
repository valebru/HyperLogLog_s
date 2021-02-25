#!/bin/bash

echo "\n\n=======================================================================\n"
echo "----------Starting VPP"
echo "\n\n=======================================================================\n"
sudo killall vpp_main
sleep 2
sudo $BINS/vpp `cat $STARTUP_CONF` &

sleep 8
echo "\n\n=======================================================================\n"
echo "----------Creating loopback interface"
echo "\n\n=======================================================================\n"
sudo -E $BINS/vppctl -s /run/vpp/cli.sock loop create
sudo -E $BINS/vppctl -s /run/vpp/cli.sock set int state loop0 up

echo "\n\n=======================================================================\n"
echo "----------Installing FlowFight plugin"
echo "\n\n=======================================================================\n"
sudo -E $BINS/vppctl -s /run/vpp/cli.sock hll start bits $2 mode 4 multi $1 loop0

#sudo -E $BINS/vppctl -s /run/vpp/cli.sock exec $FF_DIR/tools_vpp/vpp_script_2streams
#sudo -E $BINS/vppctl -s /run/vpp/cli.sock exec $FF_DIR/tools_vpp/vpp_script_pcap
#sudo -E $BINS/vppctl -s /run/vpp/cli.sock hll count
#sudo -E $BINS/vppctl -s /run/vpp/cli.sock 

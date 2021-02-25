#!/bin/bash

echo "\n\n=======================================================================\n"
echo "----------Starting VPP"
echo "\n\n=======================================================================\n"
sudo killall vpp_main
sleep 2
sudo $BINS/vpp `cat $STARTUP_CONF2` &

sleep 8
echo "\n\n=======================================================================\n"
echo "----------Cross-connecting interfaces"
echo "\n\n=======================================================================\n"
echo "Setting Up interfaces"
sudo -E $BINS/vppctl -s /run/vpp/cli.sock set int state TenGigabitEthernetd8/0/1 up
sudo -E $BINS/vppctl -s /run/vpp/cli.sock set int state TenGigabitEthernetd8/0/0 up

echo "Setting Xconnect 0->1"
sudo -E $BINS/vppctl -s /run/vpp/cli.sock set int l2 xconnect TenGigabitEthernetd8/0/1 TenGigabitEthernetd8/0/0
echo "Setting Xconnect 1->0"
sudo -E $BINS/vppctl -s /run/vpp/cli.sock set int l2 xconnect TenGigabitEthernetd8/0/0 TenGigabitEthernetd8/0/1

echo "\n\n=======================================================================\n"
echo "----------Installing FlowFight plugin"
echo "\n\n=======================================================================\n"
sudo -E $BINS/vppctl -s /run/vpp/cli.sock hll start bits $2 mode 4 multi $1 TenGigabitEthernetd8/0/1

#sudo -E $BINS/vppctl -s /run/vpp/cli.sock exec $FF_DIR/tools_vpp/vpp_script_2streams
#sudo -E $BINS/vppctl -s /run/vpp/cli.sock exec $FF_DIR/tools_vpp/vpp_script_pcap
#sudo -E $BINS/vppctl -s /run/vpp/cli.sock hll count
#sudo -E $BINS/vppctl -s /run/vpp/cli.sock 

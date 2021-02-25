# VPP test using loopback
This kind of test will create an internal loopback inside VPP and can be executed without requiring particular server features.
It can be used to play and test the accuracy of the algorithm.

### VPP startup
Enter the `tools_vpp` directory.

1. Before run vpp, please check the startup.conf file in which the vpp configuration is contained. In this directory you can find a simple startup.conf that should works with our base test.
Anyway, in the startup.conf is stored information used by VPP to configure the framework, take a look to [their documentation: detailed list of options for startup-conf file](https://wiki.fd.io/view/VPP/Command-line_Arguments)

2. To launch and configure the FlowFight plugin you can run (or take a look to the command in the bash script): `sh run_vpp_ff.sh <ff_size> <hll_bits_size>`
If you want enter the vpp command line: `sudo -E $BINS/vppctl -s /run/vpp/cli.sock`

3. Finally, to generate traffic from the VPP packet generator (the synthetic stream or the real pcap): 
```
sudo -E $BINS/vppctl -s /run/vpp/cli.sock exec $FF_DIR/tools_vpp/vpp_script_2streams
sudo -E $BINS/vppctl -s /run/vpp/cli.sock exec $FF_DIR/tools_vpp/vpp_script_pcap
```

4. To extract statistics from the FF plugin: `sudo -E $BINS/vppctl -s /run/vpp/cli.sock hll count`

5. To kill VPP: `sudo killall vpp_main`


### Results processing
In the `tools_res` directory, we prepare the reference files to the two stream we generated in vpp. This files contain the exact counting of the flows cardinality. And we will use this information to compare the FlowFight estimation with the exact estimation and evaluate the precision of the top-k and the relative error of the single HLL assigned to the flow.

We also prepared two scripts in `tools_vpp` directory, that perform the complete test:
```bash
sh start_basetest.sh
sh start_basetest_pcap.sh
```

---

# VPP test using real interface through DPDK and MoonGen
This test will use the physical interfaces to run experiment at line speed to evaluate performance of the VPP plugin. (In particular, we will evaluate the packets per second sustained by the framework).
This test requires that your physical interfaces can be binded by DPDK. And to run the test you have to first know the pci addresses of your interfaces and bind them with dpdk. [DPDK documentation for interface binding](https://doc.dpdk.org/guides/tools/devbind.html)


### VPP startup
Enter the `tools_vpp` directory.

1. Before run vpp, please check the `startup_dpdk.conf` file in which the vpp configuration is contained. (You should modify this file with your pci driver) 
Anyway, in the startup.conf is stored information used by VPP to configure the framework, take a look to [their documentation: detailed list of options for startup-conf file](https://wiki.fd.io/view/VPP/Command-line_Arguments)

2. To launch and configure the FlowFight plugin you can run (or take a look to the command in the bash script): `sh run_vpp_ff_dpdk.sh <ff_size> <hll_bits_size>`
If you want enter the vpp command line: `sudo -E $BINS/vppctl -s /run/vpp/cli.sock`

3. To extract statistics from the FF plugin: `sudo -E $BINS/vppctl -s /run/vpp/cli.sock hll count`

4. To kill VPP: `sudo killall vpp_main`

### MoonGen packets generation
The `${MoonGen_dir}` is not present in the repository and refers to the MoonGen installation directory that you should have install in the requirements part. To generate packets we need interfaces not used by VPP and they must be connected in cross-connect with the ones used by VPP.
Therefore, we need to configure the dpdkfile as we do for the `startup_dpdk.conf` with the pci addresses of your interfaces.

```bash
sudo ${MoonGen_dir}/MoonGen/build/MoonGen ${MGSCR}/replay-pcap-hll.lua --dpdk-config=${dpdkfile} 0 1 ${tracefile} ${tracefile} ${tracefile} -l
```


### Results processing
In the `tools_res` directory, we prepare the reference files to the two stream we generated in vpp. This files contain the exact counting of the flows cardinality. And we will use this information to compare the FlowFight estimation with the exact estimation and evaluate the precision of the top-k and the relative error of the single HLL assigned to the flow.

We also prepared the script in `tools_vpp` directory, that performs the complete test:
```bash
sh start_dpdktest_pcap.sh
```

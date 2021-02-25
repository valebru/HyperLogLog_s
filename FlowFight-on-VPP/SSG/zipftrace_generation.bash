path=./traceset-zipf/
spath=./traceset-zipf/shuffled/
ppath=./traceset-zipf/pcap_split/

for zipf_a in "1.1" #"1.4" "1.8" "2.1" "2.5" "3.0"
do

	echo ${zipf_a}

	pathsrc=${path}/hll-${zipf_a}-zipf/
	spathsrc=${spath}/hll-${zipf_a}-zipf/
	ppathsrc=${ppath}/hll-${zipf_a}-zipf/
	mkdir -p ${pathsrc}
	mkdir -p ${spathsrc}
	mkdir -p ${ppathsrc}


	for size in 1000000 #2500000 5000000 6000000 7000000
	do

		echo "==== ${size}_${zipf_a} ===="

		file=${pathsrc}/Hll-${zipf_a}_${size}
		sfile=${spathsrc}/Hll-${zipf_a}_${size}
		pfile=${ppathsrc}/Hll-${zipf_a}_${size}
		touch $file

		reffile=${ppathsrc}/reference-py/Hll-${zipf_a}_${size}
		mkdir -p ${ppathsrc}/reference-py

		python2.7 create_zipf_traceset.py ${file} ${size} ${zipf_a}

		for rep in {1..5}
		do
			#Traceset shuffling
			echo Traceset shuffling
			python shuffling.py $file > ${sfile}_seed${rep}.trace

			#PCAP generation
			echo PCAP generation
			sudo rm /dev/hugepages/*
			sleep 2

			sudo MoonGen ${FF_DIR}/MoonGen_parser//pcap_gen_shot3.lua --dpdk-config=dpdk-conf.lua ${sfile}_seed${rep}.trace
			mv tmp-tcp.pcap ${pfile}_seed${rep}-tcp.pcap
			mv tmp-udp.pcap ${pfile}_seed${rep}-udp.pcap
			mv tmp-icmp.pcap ${pfile}_seed${rep}-icmp.pcap

		done

		#Reference file generation
		echo Reference file generation
		touch tmp_z_merged.pcap
		mergecap -F libpcap  -a -w tmp_z_merged.pcap ${pfile}_seed1-tcp.pcap ${pfile}_seed1-udp.pcap ${pfile}_seed1-icmp.pcap
		python2.7 exact-counting_pcap.py tmp_z_merged.pcap ${reffile}.out --parsing_mode 1
		rm tmp_z_merged.pcap

		mv $file ${file}.trace

	done
done



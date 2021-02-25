To parse results and compare with the reference files obtained in the SSG directory we prepare the following python code.
```
python2.7 parser_hll.py <result_file> <output_file> <reference_file>

```

This python code, as shown below, gives the first 5 elements not monitored, the top-k precision and the relative/absolute error in the estimation of the single flow from the HLL data structure.
```
--------
Printing the first 5 elements not captured in the real first top-k (k,y)
--------
[key     exact_value     index_in_topk]

--------
Summary:
--------
Precision: []
Relative error: []
Absolute error: []
```

---

## To generate reference file

```
python2.7 ../SSG/exact-counting_pcap.py vpp_generator_capture.pcap vpp_generator_capture_ref.txt
python2.7 ../SSG/exact-counting_pcap.py <pcap_file> <output_ref_file> [--parsing_mode <1-4>]
```

## To evaluate results
```
python2.7 $FF_DIR/tools_res/parser_hll.py ../Results/Basetest_res_22-09_11-12.txt output.txt vpp_generator_capture_ref.txt

```


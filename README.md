# HyperLogLog_s
In this repository, different version of the HyperLogLog (HLL) sketch are presented. Sketches are implemented in python with a simple software simulator that takes in input a pcap trace and fill the sketch.

## HyperLogLog (HLL)
HLL is an efficient structure to estimate the cardinality of a set. It is based on the use of hash functions and requires a very limited amount of memory. HLL is based on the probabilistic counting method developed by  Flajolet and Martin~\cite{flajolet1985probabilistic}. To understand the HLL, we start from the description of the probabilistic counting method. The counting method performs the hash $h(x)$ of an incoming item $x$ and estimate the number of distinct items depending on the value of $h(x)$. In particular, we compute $\rho(h(x))$, where the function $\rho$ returns the position of the leftmost 1 in the binary representation of $h(x)$. After, it stores the maximum between the current max value and the new $\rho(h(x))$ value. At the end of the computation, the number of distinct items can be estimated as $2^{max_i(\rho(h(x_i)))}$. In fact, it is easy to understand that the probability that the function $\rho(h(x))$ gets a specific value $n$ is  $2^{-n}$. Hence, from a statistical point of view, after seeing $n$ distinct elements, the function $max_i(\rho(h(x_i)))$ roughly approximates the $log_2$ of the number of distinct elements. However, the simple method explained above suffers of a large error variability due to the use of a single memory element where the maximum $\rho$ value is stored. The HLL supersedes this limitation by: i) dividing the input stream in $m$ substreams and associating a register to each substream, and ii) performing the harmonic average among the results collected by the different $m$ substreams.

```latex
  E = \alpha_{m} \cdot m^2 \cdot Z^{-1}
    Z = \sum_{j=1}^{m} 2^{-reg[j]}   
```

The HLL can provide a relative accuracy (the standard error) in the order of  $1.04/\sqrt{m}$. As an example, HLL can estimate cardinalities of $10^9$ with a typical accuracy of $5\%$ using a memory of only 256 bytes. The small footprint and the use of hardware friendly primitives like hash functions suggest that the HLL can be easily used as a technique to estimate cardinalities without compromising the performance.

```
Flajolet, P., Fusy, É., Gandouet, O., & Meunier, F. (2007, June). Hyperloglog: the analysis of a near-optimal cardinality estimation algorithm. In Discrete Mathematics and Theoretical Computer Science (pp. 137-156). Discrete Mathematics and Theoretical Computer Science.
```


## Streaming HLL

Streaming HyperLogLog (and more broadly streaming cardinality estimation) was proposed in~\cite{tingCMHLL} to improve the accuracy by estimating the cardinality as elements arrive instead of at the end of the process. Interestingly, the streaming method opens the door to new algorithms as we only need to know the probability that a new element is detected at each point to build a cardinality estimate. Let us denote a $q(S_t)$ the probability that a new element is detected by a sketch at time $t$ (in HLL that is the probability that it changes the value of the register it maps to). Then the cardinality estimation can be done by simply computing:

```
    C_{\mathit{SHLL}} = C_{\mathit{SHLL}} + \frac{1}{q(S_t)}
```

And updating $q(S_t)$ to reflect the new probability of detecting a new element. This scheme can be directly applied to HLL using:

```
    q(S_t)=\frac{\sum_{i=1}^{R} 2^{-r_i}}{R}
```

The streaming approach allows to estimate the cardinality packet per packet as they arrive. The data structure remains the same, an array of $R$ registers that are updated computing two hash functions $h(x)$ and $g(x)$. But before updating the sketch, the algorithm will compute the probability of modifying the sketch and update the estimation as in eq.~\ref{eqn:streaming}. Therefore at the end of the data stream, the cardinality estimation is already computed and the information available at each intermediate step is used to improve the estimate. It is shown how the Streaming HyperLogLog approach is able to achieve the same error as the original HyperLogLog that uses approximately $1.4426 \cdot 1.042 \approx 1.56$ times the space of the Streaming HyperLogLog. Therefore, it provides significant savings in terms of memory footprint.

```
Ting, D. (2014, August). Streamed approximate counting of distinct elements: Beating optimal batch methods. In Proceedings of the 20th ACM SIGKDD international conference on Knowledge discovery and data mining (pp. 442-451).
```


## Fast HLL
In a network it is interesting to know the different number of flows that traverse a switch or link or the number of connections coming from a specific sub-network. This is generally known as cardinality estimation or count distinct. The HyperLogLog (HLL) algorithm is widely used to estimate cardinality with a small memory footprint and simple per packet operations. However, with current line rates approaching a Terabit per second and switches handling many Terabits per second, even implementing HLL is challenging. This is mostly due to a bottleneck in accessing the memory as a random position has to be accessed for each packet. In this letter, we present and evaluate Fast Update HLL (FU-HLL), a scheme that eliminates the need to access the memory for most packets. Results show that FU-HLL can indeed significantly reduce the number of memory accesses when the cardinality is much larger than the number of registers used in HLL as it is commonly the case in practical settings.  

```
REVIRIEGO, Pedro, et al. Fast Updates for Line-Rate HyperLogLog-Based Cardinality Estimation. IEEE Communications Letters, 2020, 24.12: 2737-2741.
```


## FlowFight (a top-k structure that uses HLLs)
A recurring task in security monitoring / anomaly detection applications consists in finding the so-called top  ``Spreaders'' (``Scanners''), for instance hosts which connect to a large number of distinct destinations or hit different ports. Estimating the top $k$ scanners, and their cardinality, using the least amount of memory meanwhile running at multi-Gbps speed, is a non trivial task, as it requires to ``remember'' the destinations or ports already hit in the past by each specific host. This paper proposes and assesses an innovative design, called FlowFight. As the name implies, our approach revolves on the idea of deploying a relatively small number of per-flow HyperLogLog approximate counters --- only slightly superior to the target $k$ --- and involve the potentially huge number of concurrent flows in a sort of dynamic randomized ``competition'' for entering such set. The algorithm has been tested and integrated in a full-fledged software router such as Vector Packet Processor. Using either synthetic as well as real traffic traces, we show that FlowFight is able to estimate the top-$k$ cardinality flows with an accuracy of more than 95\%, while retaining a processing throughput of around 8 Mpps on a single core.

```
ICIN demo 2021
```

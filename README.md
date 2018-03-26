# trace
:telephone: IP datagram analysis.

..add gif here..

## TODO
+ Identify ultimate source/destination
  + Handle identifying source/destination for both Linux/Windows
+ Identify correct order of intermediate routers
+ Compute avg RTT and standard deviation between source -> intermediate(s) and source -> destination
  + Need to store all RTTs for pairs
  + Ultimate destination (Linux: Type 3 ICMP, Windows: Type 0 ICMP)
+ Reduce use of global vars (!)
+ Thorough testing
+ Clean-up repo and add example gif
  + Make note of file support (`.pcap` vs `.pcapng`)
+ Finish R2 and add pdf

## Overview
This project was an assignment for the [Computer Communications and Networks](https://github.com/williamgrosset/trace/blob/master/csc361_p3.pdf) class at the University of Victoria. The purpose of this program is to analyze IP datagrams in a capture file. The program will echo information from the capture file such as the ultimate source and destination, intermediate routers, protocol types, round-trip times, and possible fragmented datagrams.

### Usage 
**Prerequisite**: `Python 2.7.x` (tested with `Python 2.7.10`)
1. Install [pcapy](https://github.com/CoreSecurity/pcapy) and [impacket](https://github.com/CoreSecurity/impacket).
2. Run `python main.py <capture-file>` (see [data](https://github.com/williamgrosset/trace/tree/master/data)).

# trace
:telephone: IP datagram analysis.

..add gif here..

## TODO
+ Grab ultimate destination
+ Identify correct order of intermediate routers
+ Identify all fragmented datagrams (initially make simple counter for total fragments)
  + Grab latest fragment offset
+ Compute avg RTT and standard deviation between source -> intermediate(s) and source -> destination
  + Need to store all RTTs for pairs
  + Read announcement/chatroom
  + Ultimate destination (Linux: Type 3 ICMP, Windows: Type 0 ICMP)
+ Reduce use of global vars (!)
+ Thorough testing
+ Clean-up repo and add example gif
+ FINISH R2 and add pdf
  + Make note of file support (`.pcap` vs `.pcapng`)

## Overview
This project was an assignment for the [Computer Communications and Networks](https://github.com/williamgrosset/trace/blob/master/csc361_p3.pdf) class at the University of Victoria. The purpose of this program is to identify and analyze IP datagrams in a capture file. The program will echo information such as addresses of source, destination, and intermediate hosts/routers, protocol types, fragmented datagrams, and average round-trip times.

### Usage 
**Prerequisite**: `Python 2.7.x` (tested with `Python 2.7.10`)
1. Install [pcapy](https://github.com/CoreSecurity/pcapy) and [impacket](https://github.com/CoreSecurity/impacket).
2. Run `python main.py <capture-file>` (see [data](https://github.com/williamgrosset/trace/tree/master/data)).

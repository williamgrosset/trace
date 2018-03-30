# trace
:telephone: IP datagram analysis.

<img alt="trace" src="https://user-images.githubusercontent.com/16131737/38125024-2ff2af2a-339b-11e8-9d35-85c7b9385eaa.gif" />

## TODO
+ Harder constraints on targeted packets?j
+ Error-handling
+ Clean-up repo/nits
+ Make note of file support (`.pcap` vs `.pcapng`)
+ Finish R2 and add pdf

## Overview
This project was an assignment for the [Computer Communications and Networks](https://github.com/williamgrosset/trace/blob/master/csc361_p3.pdf) class at the University of Victoria. The purpose of this program is to analyze IP datagrams in a capture file. The program will echo information from the capture file such as the source and destination, intermediate routers, protocol types, round-trip times, and fragmentation.

### Usage 
**Prerequisite**: `Python 2.7.x` (tested with `Python 2.7.10`)
1. Install [pcapy](https://github.com/CoreSecurity/pcapy) and [impacket](https://github.com/CoreSecurity/impacket).
2. Run `python main.py <capture-file>` (see [data](https://github.com/williamgrosset/trace/tree/master/data)).

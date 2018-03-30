from __future__ import division
from collections import OrderedDict
from impacket import ImpactDecoder, ImpactPacket
from results_logger import print_results
from CONSTANTS import PROTOCOL_TYPES
import pcapy
import sys

class Datagram:
    def __init__(self, timestamp, ip_header):
        self.ts = timestamp
        self.ip_header = ip_header

protocol_set = set([])
datagram_pairs_dict = OrderedDict()
fragment_dict = {}
is_initial_packet = True
is_windows = False

def calculate_rtt_sd(intermediate_list):
    print('oi')

def identify_intermediate_routers(intermediate_list):
    intermediate_ip_list = []
    for datagram_pair in intermediate_list:
        source = datagram_pair[1][1].ip_header.get_ip_src()
        if source not in intermediate_ip_list: intermediate_ip_list.append(source)
    return intermediate_ip_list

def clear_datagram_dict():
    global datagram_pairs_dict
    temp_dict = datagram_pairs_dict
    for key, value in temp_dict.iteritems():
        if value[1] == None: del temp_dict[key]
    return temp_dict

def sort_datagram_pairs():
    # Sort by TTL and timestamp
    return sorted(datagram_pairs_dict.iteritems(), key=lambda value: (value[1][0].ip_header.get_ip_ttl(), value[1][1].ts))

def identify_datagram_pairs(ts, ip_header, protocol):
    source_ip = ip_header.get_ip_src()
    destination_ip = ip_header.get_ip_dst()

    if is_windows:
        if protocol != 'ICMP':
            return

        icmp_header = ip_header.child()
        icmp_type = icmp_header.get_icmp_type()

        # ICMP Type-0 or Type-8
        if icmp_type == 0 or icmp_type == 8:
            seq_num = icmp_header.get_icmp_seq()
        # ICMP Type-11 nested with ICMP Type-8
        else:
            if icmp_type != 11:
                return

            icmp_header = ImpactDecoder.IPDecoder().decode(ip_header.child().get_data_as_string()).child()
            seq_num = icmp_header.get_icmp_seq()

        if not datagram_pairs_dict.has_key((destination_ip, seq_num)):
            datagram_pairs_dict[(source_ip, seq_num)] = (Datagram(ts, ip_header), None)
        else:
            request_datagram = datagram_pairs_dict[(destination_ip, seq_num)][0]
            datagram_pairs_dict[(destination_ip, seq_num)] = (request_datagram, Datagram(ts, ip_header))
    else:
        # UDP
        if protocol == 'UDP':
            udp_header = ip_header.child()

            if not datagram_pairs_dict.has_key((source_ip, udp_header.get_uh_sport())):
                datagram_pairs_dict[(source_ip, udp_header.get_uh_sport())] = (Datagram(ts, ip_header), None)
        # ICMP
        else:
            icmp_header = ip_header.child()
            icmp_type = icmp_header.get_icmp_type()

            # ICMP Type-3 or Type-11
            if icmp_type == 3 or icmp_type == 11:
                udp_header = ImpactDecoder.IPDecoder().decode(icmp_header.get_data_as_string()).child()
                if not datagram_pairs_dict.has_key((destination_ip, udp_header.get_uh_sport())):
                    datagram_pairs_dict[(source_ip, udp_header.get_uh_sport())] = (Datagram(ts, ip_header), None)
                else:
                    request_datagram = datagram_pairs_dict[(destination_ip, udp_header.get_uh_sport())][0]
                    datagram_pairs_dict[(destination_ip, udp_header.get_uh_sport())] = (request_datagram, Datagram(ts, ip_header))

def add_fragmented_datagram(ip_header):
    fragment_offset = ip_header.get_ip_off() * 8;
    if not ip_header.get_ip_df() and (ip_header.get_ip_mf() == 1 or fragment_offset > 0):
        # Store in dictionary: identification # -> (count, fragment_offset)
        identification = ip_header.get_ip_id()
        if not fragment_dict.has_key(identification):
            fragment_dict[identification] = (1, fragment_offset)
        else:
            fragment_dict[identification] = (fragment_dict[identification][0] + 1, fragment_offset)

def handle_packets(header, data):
    decoder = ImpactDecoder.EthDecoder()
    ethernet_packet = decoder.decode(data)

    if ethernet_packet.get_ether_type() != ImpactPacket.IP.ethertype:
        return

    ts = header.getts()[0] + (header.getts()[1] / 1000000)
    ip_header = ethernet_packet.child()
    protocol = ip_header.get_ip_p()
    protocol_type = PROTOCOL_TYPES[protocol]

    # Only target UDP/ICMP packets (ignore DNS)
    if (protocol_type == 'ICMP' and not ip_header.child().get_icmp_type() == 9) or (protocol_type == 'UDP' and not
     (ip_header.child().get_uh_sport() == 53 or ip_header.child().get_uh_dport() == 53)):
        # Identify if Windows capture file
        if is_initial_packet and protocol_type == 'ICMP' and ip_header.child().get_icmp_type() == 8:
            global is_windows
            is_windows = True

        # Identify initial_packet
        if is_initial_packet:
            global is_initial_packet
            is_initial_packet = False

        # Identify pairs for ICMP/ICMP or UDP/ICMP datagrams
        identify_datagram_pairs(ts, ip_header, protocol_type)

        # Identify datagram fragments and last fragment offset
        add_fragmented_datagram(ip_header)

        # Add protocol type to set
        protocol_set.add(protocol)

def main():
    filename = sys.argv[1]
    try:
        pc = pcapy.open_offline(filename)
    except Exception as e:
        print('Cannot open capture file: %s' % filename)
        sys.exit(1)

    pc.dispatch(-1, handle_packets)
    datagram_pairs_dict = clear_datagram_dict()
    intermediate_list = sort_datagram_pairs()
    intermediate_set = identify_intermediate_routers(intermediate_list)
    print_results(intermediate_list, intermediate_set, protocol_set, fragment_dict)

if __name__ == '__main__':
    main()

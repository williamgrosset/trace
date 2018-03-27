from impacket import ImpactDecoder, ImpactPacket
import pcapy
import sys

ult_source = ''
ult_destination = ''
intermediate_list = []
fragment_dict = {}
datagram_pairs_dict = {}
protocol_set = set([])
# TODO: Exclude support for TCP/IGMP
PROTOCOL_TYPES = {
    1: 'ICMP',
    2: 'IGMP',
    6: 'TCP',
    17: 'UDP'
}

def print_results():
    print('The IP address of the source node:')
    print('The IP address of ultimate destination node:')
    print('The IP addresses of the intermediate destination nodes:')
    print('The values in the protocol field of IP headers:')
    print('The number of fragments created from the original datagram is:')
    print('The offset of the last fragment is:')
    print('The avg RTT between IP HERE and IP HERE is: VALUE ms, the s.d. is: VALUE ms')

#def calculate_round_trip_time():

def receive_packets(header, data):
    decoder = ImpactDecoder.EthDecoder()
    ethernet_packet = decoder.decode(data)

    if ethernet_packet.get_ether_type() != ImpactPacket.IP.ethertype:
        return

    ip_header = ethernet_packet.child()
    source = ip_header.get_ip_src()
    destination = ip_header.get_ip_dst()
    protocol = ip_header.get_ip_p()
    identification = ip_header.get_ip_id()
    offset = ip_header.get_ip_off() * 8;
    protocol_type = PROTOCOL_TYPES[protocol]

    # Only target UDP/ICMP packets (ignore DNS)
    if protocol_type == 'ICMP' or (protocol_type == 'UDP' and not
     (ip_header.child().get_uh_sport() == 53 or ip_header.child().get_uh_dport() == 53)):
        # Identify ultimate source
        if not ult_source:
            global ult_source
            ult_source = source

        # Identify ultimate destination
        if not ult_destination:
            global ult_destination
            ult_destination = destination

        # TODO: Grab all appropriate pairs for UDP/ICMP or ICMP/ICMP match
        # TEMPO: LINUX SUPPORT
        # IF UDP
        if protocol_type == 'UDP':
            if not datagram_pairs_dict.has_key((source, ip_header.child().get_uh_sport())):
                print(ip_header.child().get_uh_sport())
                datagram_pairs_dict[(source, ip_header.child().get_uh_sport())] = (ip_header, None)
            #else:
                #og_ip_header = datagram_pairs_dict[(destination, ip_header.child().get_uh_sport())][0]
                #datagram_pairs_dict[(destination, ip_header.child().get_uh_sport())] = (og_ip_header, ip_header)
        # ELSE ICMP
        else:
            udp_header = ImpactDecoder.IPDecoder().decode(ip_header.child().get_data_as_string()).child()

            if not datagram_pairs_dict.has_key((destination, udp_header.get_uh_sport())):
                datagram_pairs_dict[(source, udp_header.get_uh_sport())] = (ip_header, None)
            else:
                og_ip_header = datagram_pairs_dict[(destination, udp_header.get_uh_sport())][0]
                datagram_pairs_dict[(destination, udp_header.get_uh_sport())] = (og_ip_header, ip_header)

        # Identify intermediate(s)
        if (source not in intermediate_list and destination == ult_source and protocol_type == 'ICMP' and
         ip_header.child().get_icmp_type() == 11):
            intermediate_list.append(source)

        # Add protocol type to set
        protocol_set.add(protocol)

        # Identify datagram fragments and last fragment offset
        if not ip_header.get_ip_df() and (ip_header.get_ip_mf() == 1 or offset > 0):
            # Store in dictionary: identification # -> (count, offset)
            if not fragment_dict.has_key(identification):
                fragment_dict[identification] = (1, offset)
            else:
                count = fragment_dict[identification][0]
                count += 1
                fragment_dict[identification] = (count, offset)

def main():
    filename = sys.argv[1]
    try:
        pc = pcapy.open_offline(filename)
    except Exception as e:
        print('Cannot open capture file: %s' % filename)
        sys.exit(1)

    pc.dispatch(-1, receive_packets)
    print(ult_source)
    print(ult_destination)
    print(intermediate_list)
    print(fragment_dict)
    print(datagram_pairs_dict.values()[0])
    print(datagram_pairs_dict.values()[0][0])
    print(datagram_pairs_dict.values()[0][1])
    print(protocol_set)

if __name__ == '__main__':
    main()

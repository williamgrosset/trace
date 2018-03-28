from impacket import ImpactDecoder, ImpactPacket
import pcapy
import sys

# TODO: Remove support for non-required types
PROTOCOL_TYPES = {
    1: 'ICMP',
    2: 'IGMP',
    6: 'TCP',
    17: 'UDP'
}

ult_source_ip = ''          # Temporary (?)
ult_destination_ip = ''     # Temporary (?)
protocol_set = set([])
fragment_dict = {}
datagram_pairs_dict = {}
is_windows = False

def print_results():
    print('The IP address of the source node:')
    print('The IP address of ultimate destination node:')
    print('The IP addresses of the intermediate destination nodes:')
    print('The values in the protocol field of IP headers:')
    print('The number of fragments created from the original datagram is:')
    print('The offset of the last fragment is:')
    print('The avg RTT between IP HERE and IP HERE is: VALUE ms, the s.d. is: VALUE ms')

def receive_packets(header, data):
    decoder = ImpactDecoder.EthDecoder()
    ethernet_packet = decoder.decode(data)

    if ethernet_packet.get_ether_type() != ImpactPacket.IP.ethertype:
        return

    ip_header = ethernet_packet.child()
    protocol = PROTOCOL_TYPES[ip_header.get_ip_p()]

    # Only target UDP/ICMP packets (ignore DNS)
    if protocol == 'ICMP' or (protocol == 'UDP' and not
     (ip_header.child().get_uh_sport() == 53 or ip_header.child().get_uh_dport() == 53)):
        source_ip = ip_header.get_ip_src()
        destination_ip = ip_header.get_ip_dst()
        fragment_offset = ip_header.get_ip_off() * 8;

        # Identify if Windows capture file
        if not ult_source_ip and not ult_destination_ip and protocol == 'ICMP' and ip_header.child().get_icmp_type() == 8:
            global is_windows
            is_windows = True

        # Identify ultimate source
        if not ult_source_ip:
            global ult_source_ip
            ult_source_ip = source_ip

        # Identify ultimate destination
        if not ult_destination_ip:
            global ult_destination_ip
            ult_destination_ip = destination_ip

        # Add protocol type to set
        protocol_set.add(protocol)

        # TODO: Grab all appropriate pairs for UDP/ICMP or ICMP/ICMP match
        if not is_windows:
            # IF UDP
            if protocol == 'UDP':
                if not datagram_pairs_dict.has_key((source_ip, ip_header.child().get_uh_sport())):
                    datagram_pairs_dict[(source_ip, ip_header.child().get_uh_sport())] = (ip_header, None)
            # ELSE ICMP
            else:
                udp_header = ImpactDecoder.IPDecoder().decode(ip_header.child().get_data_as_string()).child()
                if not datagram_pairs_dict.has_key((destination_ip, udp_header.get_uh_sport())):
                    datagram_pairs_dict[(source_ip, udp_header.get_uh_sport())] = (ip_header, None)
                else:
                    request_ip_header = datagram_pairs_dict[(destination_ip, udp_header.get_uh_sport())][0]
                    datagram_pairs_dict[(destination_ip, udp_header.get_uh_sport())] = (request_ip_header, ip_header)

        # TODO: Identify datagram fragments and last fragment offset
        if not ip_header.get_ip_df() and (ip_header.get_ip_mf() == 1 or fragment_offset > 0):
            # Store in dictionary: identification # -> (count, fragment_offset)
            identification = ip_header.get_ip_id()
            if not fragment_dict.has_key(identification):
                fragment_dict[identification] = (1, fragment_offset)
            else:
                fragment_dict[identification] = (fragment_dict[identification][0] + 1, fragment_offset)

def main():
    filename = sys.argv[1]
    try:
        pc = pcapy.open_offline(filename)
    except Exception as e:
        print('Cannot open capture file: %s' % filename)
        sys.exit(1)

    pc.dispatch(-1, receive_packets)
    print(ult_source_ip)
    print(ult_destination_ip)
    print(fragment_dict)
    print(datagram_pairs_dict)
    print(protocol_set)

if __name__ == '__main__':
    main()

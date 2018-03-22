from impacket import ImpactDecoder, ImpactPacket
import sys
import pcapy

ult_source = ''
ult_destination = ''
intermediate_set = set([])
protocol_set = set([])
PROTOCOL_TYPE = {
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

def calculate_round_trip_time():
    print()

def receive_packets(header, data):
    decoder = ImpactDecoder.EthDecoder()
    ethernet_packet = decoder.decode(data)

    if ethernet_packet.get_ether_type() != ImpactPacket.IP.ethertype:
        return

    print(ethernet_packet)

    ip_header = ethernet_packet.child()
    source = ip_header.get_ip_src()
    protocol = ip_header.get_ip_p()

    # Identify source
    if not ult_source and PROTOCOL_TYPE[protocol] == 'UDP':
        global ult_source
        ult_source = source

    # TODO: Identify destination

    # TODO: Identify intermediate(s)

    # Add protocol type to set
    protocol_set.add(protocol)

    # TODO: Identify datagram fragments and last fragment offset

def main():
    filename = sys.argv[1]
    try:
        pc = pcapy.open_offline(filename)
    except Exception as e:
        print('Cannot open capture file: %s' % filename)
        sys.exit(1)

    pc.dispatch(-1, receive_packets)
    #calculate_round_trip_time()
    #print_results()

    # Testing
    print(protocol_set)
    print(ult_source)

if __name__ == '__main__':
    main()

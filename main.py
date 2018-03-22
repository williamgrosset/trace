from impacket import ImpactDecoder, ImpactPacket
import sys
import pcapy

PROTOCOL_TYPE = {
    1: 'ICMP',
    2: 'IGMP',
    6: 'TCP',
    17: 'UDP'
}
protocols = set([])
ult_source = ''
ult_destination = ''
intermediate_list = []

def print_results(addresses, protocols, round_trip_times):
    print('The IP address of the source node:')
    print('The IP address of ultimate destination node:')
    print('The IP addresses of the intermediate destination nodes:')

    # TODO: Sort by increasing order of protocol value
    print('The values in the protocol field of IP headers:')

    print('The number of fragments created from the original datagram is:')

    print('The offset of the last fragment is:')

    print('The avg RTT between IP HERE and IP HERE is: VALUE ms, the s.d. is: VALUE ms')

def receive_packets(header, data):
    decoder = ImpactDecoder.EthDecoder()
    ethernet_packet = decoder.decode(data)

    if ethernet_packet.get_ether_type() != ImpactPacket.IP.ethertype:
        return

    print(ethernet_packet)

    ip_header = ethernet_packet.child()
    source = ip_header.get_ip_src()
    protocol = ip_header.get_ip_p()

    protocols.add(protocol)
    if not ult_source and PROTOCOL_TYPE[protocol] == 'UDP':
        global ult_source
        ult_source = source

def main():
    filename = sys.argv[1]
    try:
        pc = pcapy.open_offline(filename)
    except Exception as e:
        print('Cannot open capture file: %s' % filename)
        sys.exit(1)

    pc.dispatch(-1, receive_packets)
    print(protocols)
    print(ult_source)

if __name__ == '__main__':
    main()

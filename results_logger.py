from CONSTANTS import PROTOCOL_TYPES

def print_results(intermediate_list, intermediate_set, protocol_set, fragment_dict):
    list_length = len(intermediate_list)
    source = intermediate_list[list_length - 1][1][0].ip_header.get_ip_src()
    destination = intermediate_list[list_length - 1][1][1].ip_header.get_ip_src()

    print('The IP address of the source node: %s' % source)
    print('The IP address of ultimate destination node: %s' % destination)
    print('The IP addresses of the intermediate destination nodes:')
    for index in range(len(intermediate_set) - 1):
        print('\trouter %i: %s' % (index + 1, intermediate_set[index]))

    print('\n')

    print('The values in the protocol field of IP headers:')
    for protocol in protocol_set:
        print('\t%i: %s' % (protocol, PROTOCOL_TYPES[protocol]))

    print('\n')

    if fragment_dict:
        print('The number of fragments created from the original datagram is:')
        print('The offset of the last fragment is:')

        print('\n')

    print('The avg RTT between IP HERE and IP HERE is: VALUE ms, the s.d. is: VALUE ms')

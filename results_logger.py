from CONSTANTS import PROTOCOL_TYPES

def print_addresses(intermediate_list, intermediate_set):
    list_length = len(intermediate_list)
    source = intermediate_list[list_length - 1][1][0].ip_header.get_ip_src()
    destination = intermediate_list[list_length - 1][1][1].ip_header.get_ip_src()

    print('The IP address of the source node: %s' % source)
    print('The IP address of ultimate destination node: %s' % destination)
    print('The IP addresses of the intermediate destination nodes:')

    for index in range(len(intermediate_set) - 1):
        print('\trouter %i: %s' % (index + 1, intermediate_set[index]))

    print('\n')

def print_protocol_types(protocol_set):
    print('The values in the protocol field of IP headers:')
    for protocol in protocol_set:
        print('\t%i: %s' % (protocol, PROTOCOL_TYPES[protocol]))
    print('\n')

def print_fragmentation(fragment_dict):
    i = 1
    if fragment_dict:
        print('The number of fragments created from the original datagram D%i is:' % i)
        print('The offset of the last fragment is:\n')
        i += 1

def print_statistics():
    print('The avg RTT between IP HERE and IP HERE is: VALUE ms, the s.d. is: VALUE ms')

def print_results(intermediate_list, intermediate_set, protocol_set, fragment_dict):
    print_addresses(intermediate_list, intermediate_set)
    print_protocol_types(protocol_set)
    print_fragmentation(fragment_dict)
    print_statistics()

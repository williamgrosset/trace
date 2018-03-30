from CONSTANTS import PROTOCOL_TYPES

def print_addresses(source_ip, destination_ip, intermediate_set):
    print('The IP address of the source node: %s' % source_ip)
    print('The IP address of ultimate destination node: %s' % destination_ip)
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
    for key, value in fragment_dict.iteritems():
        print('The number of fragments created from the original datagram D%i is:' % (i, value[0]))
        print('The offset of the last fragment is: %i\n' % value[1])
        i += 1

def print_statistics(source_ip, rtt_dict):
    for key, value in rtt_dict.iteritems():
        print('The avg RTT between %s and %s is: %i ms, the s.d. is: %i ms' % (source_ip, key, value[0], value[1]))

def print_results(source_ip, destination_ip, intermediate_set, protocol_set, fragment_dict, rtt_dict):
    print_addresses(source_ip, destination_ip, intermediate_set)
    print_protocol_types(protocol_set)
    print_fragmentation(fragment_dict)
    print_statistics(source_ip, rtt_dict)

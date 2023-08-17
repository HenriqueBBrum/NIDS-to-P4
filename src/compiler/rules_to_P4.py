# This program converts NIDS rules to P4 table entries, removes duplicates and groups them.

from ipaddress import ip_network, ip_address, IPv4Address
import socket
import struct

from P4_related_classes import *

PROTO_MAPPING = {'icmp': 1, 'ip': 4, 'tcp': 6, 'udp': 17}
IPv4_ETHER_TYPE = 2048
IPv6_ETHER_TYPE = 34525

MAX_PRIORITY = 4 # NIDS rules max priority


# Creates all table entries from the NIDS rules
def rules_to_P4_table_match(rules, config):
    ipv4_P4_table_match_list, ipv6_P4_table_match_list = [], []
    for parsed_rule in rules:
        ipv4_match, ipv6_match = _rule_to_P4_table_match(parsed_rule)

        ipv4_P4_table_match_list.extend(ipv4_match)
        ipv6_P4_table_match_list.extend(ipv6_match)

    return ipv4_P4_table_match_list, ipv6_P4_table_match_list

# Flattens snort rules to multiple p4 table entries
def _rule_to_P4_table_match(parsed_rule):
    proto = parsed_rule.header.get('proto')
    if proto not in PROTO_MAPPING:
        print("No mapping for proto {}".format(proto))
        return [], []
        
    src_ip_list = parsed_rule.header.get('src_ip')
    src_port_list = parsed_rule.header.get('src_port')
    dst_ip_list = parsed_rule.header.get('dst_ip')
    dst_port_list = parsed_rule.header.get('dst_port')

    ipv4_flat_P4_rules, ipv6_flat_P4_rules = [], []
    for src_ip in src_ip_list:
        for dst_ip in dst_ip_list:
            if _ip_address_type(src_ip[0]) != _ip_address_type(dst_ip[0]):
                    print("IPs in different version")
                    continue
                
            for src_port in src_port_list:
                for dst_port in dst_port_list:
                    P4_rule_match = _create_P4_table_match(proto, src_ip[0], src_port[0], dst_ip[0], dst_port[0], parsed_rule.flags)
                    P4_rule = P4AggregatedMatch(P4_rule_match, parsed_rule.priority_list, parsed_rule.sid_rev_list)

                    if _ip_address_type(src_ip[0]) == IPv4Address:
                        ipv4_flat_P4_rules.append(P4_rule)
                    else:
                        ipv6_flat_P4_rules.append(P4_rule)


    return ipv4_flat_P4_rules, ipv6_flat_P4_rules

# Checks the type of a string representing an IP address
def _ip_address_type(ip):
    no_network = ip.split("/")[0]
    return type(ip_address(no_network))

# Converts the Snort rule header values to a P4Match class
def _create_P4_table_match(proto, src_ip, src_port, dst_ip, dst_port, flags):
    p4_match_rule = P4Match()
    p4_match_rule.proto = PROTO_MAPPING.get(proto, None)
    if proto == 'ip':
        if _ip_address_type(src_ip) == IPv4Address:
            p4_match_rule.proto = IPv4_ETHER_TYPE
        else:
            p4_match_rule.proto = IPv6_ETHER_TYPE


    p4_match_rule.src_network, p4_match_rule.src_addr, p4_match_rule.src_addr_mask = _get_IP_address_and_mask(src_ip)
    p4_match_rule.src_port = src_port

    p4_match_rule.dst_network, p4_match_rule.dst_addr, p4_match_rule.dst_addr_mask = _get_IP_address_and_mask(dst_ip)
    p4_match_rule.dst_port= dst_port

    p4_match_rule.flags =  _convert_TCP_flags_to_binary(flags)

    return p4_match_rule

# Separates a CIDR based IP into an address and a mask
def _get_IP_address_and_mask(_ip):
    if _ip_address_type(_ip) == IPv4Address:
        if "/" not in _ip:
            _ip += "/32"
        IP_type = socket.AF_INET
    else:
        if "/" not in _ip:
            _ip += "/128"
        IP_type = socket.AF_INET6

    network = ip_network(_ip, False)
    try:
        addr, net_bits = _ip.split('/')
        host_bits = 32 - int(net_bits)
        mask = socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << host_bits)))
        return network, addr, mask
    except Exception as e:
        print("Error on ip network {}: {}".format(ip_network, e))

    return _get_IP_address_and_mask('255.255.255.255')

# Not supported
#     + - ALL flag, match on all specified flags plus any others
#     * - ANY flag, match on any of the specified flags
#     ! - NOT flag, match if the specified flags aren't set in the packet
def _convert_TCP_flags_to_binary(flags_input, rule=None):
    supported_flag_values = {
        'F': 1,
        'S': 2,
        'R': 4, 
        'P': 8,
        'A': 16,
        'U': 32,
        '2': 64,
        '1': 128,
    }

    flags = list(''.join(flags_input).replace(' ', ''))

    # If no flag set, allow any value
    if len(flags) == 0:
        return f'{0x00:0>8b}'
    
    # Test for not supported characters
    invalid_flags = [invalid_flag for invalid_flag in flags
                     if invalid_flag not in supported_flag_values]

    if len(invalid_flags) != 0:
        print("Not supported flags {} found in {} from {} - {}".format(invalid_flags, flags, flags_input, rule))
        return f'{0x00:0>8b}'

    result_value = 0
    for flag in flags:
        flag_value = supported_flag_values[flag]
        result_value += flag_value
    return f'{result_value:0>8b}'




# Deduplicates P4 table entries with the same match. Saves each duplicate rule's priority and sid/rev in a P4AggregatedMatch object
def dedup_table_matches(rules):
    deduped_p4_rules = {}
    for rule in rules:
        rule_match = rule.match.to_string()
       
        if rule_match not in deduped_p4_rules:
            deduped_p4_rules[rule_match] = P4AggregatedMatch(rule.match, [], [])
        
        deduped_p4_rules[rule_match].priority_list.extend(rule.priority_list)
        deduped_p4_rules[rule_match].sid_rev_list.extend(rule.sid_rev_list)

    return list(deduped_p4_rules.values())
   



# Remove P4 table entries that have the same fields as another entry and are within the port or IP range of that entry
def reduce_table_matches(rules):
    rules_list = []
    rules_groupped = {}
    for rule in rules:
        rules_list.append(rule)

    for rule in rules_list:
        new_group = True
        for key, rule_group in rules_groupped.copy().items():
            if _is_rule_within(rule, rule_group):
                rules_groupped[rule_group.match.to_string()].sid_rev_list.extend(rule.sid_rev_list)
                rules_groupped[rule_group.match.to_string()].priority_list.extend(rule.priority_list)

                new_group = False
                break
            elif _is_rule_within(rule_group, rule):
                if rule.match.to_string() not in rules_groupped:
                    rules_groupped[rule.match.to_string()] = rule
                    rules_groupped[rule.match.to_string()].sid_rev_list.extend(rule_group.sid_rev_list)
                    rules_groupped[rule.match.to_string()].priority_list.extend(rule_group.priority_list)

                del rules_groupped[rule_group.match.to_string()]

                new_group = False

        if new_group:
            rules_groupped[rule.match.to_string()] = rule

    return list(rules_groupped.values())

# Is rule1 within rule2? Is rule1's IP or port within rule's2 IP or por range(space)
def _is_rule_within(rule1, rule2):
    r1_match = rule1.match
    r2_match = rule2.match

    if r1_match.proto != r2_match.proto:
        return False

    r1_src_port_start, r1_src_port_end = _get_port_range_start_end(r1_match.src_port)
    r2_src_port_start, r2_src_port_end = _get_port_range_start_end(r2_match.src_port)

    if not (r1_src_port_start >= r2_src_port_start and r1_src_port_end <= r2_src_port_end):
        return False

    r1_dst_port_start, r1_dst_port_end = _get_port_range_start_end(r1_match.dst_port)
    r2_dst_port_start, r2_dst_port_end = _get_port_range_start_end(r2_match.dst_port)

    if not (r1_dst_port_start >=r2_dst_port_start and r1_dst_port_end <= r2_dst_port_end):
        return False


    if type(r1_match.src_network) != type(r2_match.src_network) or type(r1_match.dst_network) != type(r2_match.dst_network):
        return False

    if not r1_match.src_network.subnet_of(r2_match.src_network):
        return False

    if not r1_match.dst_network.subnet_of(r2_match.dst_network):
        return False

    if not (r1_match.flags == r2_match.flags):
        return False

    return True

# Get the start and end of a range type
def _get_port_range_start_end(port):
    if isinstance(port, range):
        return port.start, port.stop-1
    else:
        return int(port), int(port)




# Creates the final table entries with the tablename, action, match, and priority
# WARNING
# Snort priority is as follows:
#          1 - High
#          2 - Medium
#          3 - Low
#          4 - Very low
# P4 tables have the inverse priority behavior:
#          1 - Very Low
#          2 - Low
#          3 - Medium
#          4 - High
def create_table_entries(rules, table_name):
    count = 0
    sids, rules_qnt, table_entries = [], [], []
    for rule in rules:
        count += 1
        table_entry = P4TableEntry(table=table_name,
                                       action='redirect',
                                       priority=(MAX_PRIORITY - rule.min_priority()),
                                       agg_match=rule)
        
        table_entries.append(table_entry)

        sids.extend(rule.sid_rev())
        rules_qnt.append(len(rule.sid_rev()))

    return table_entries, sids, rules_qnt

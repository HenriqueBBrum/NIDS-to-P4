from ipaddress import ip_network, ip_address, IPv4Network


from P4_related_classes import *

PROTO_MAPPING = {'icmp': 1, 'ip': 4, 'tcp': 6, 'udp': 17}

# Flattens snort rules to multiple p4 table entries
def rules_to_P4_table_match(grouped_rules, config):
    ipv4_P4_rules, ipv6_P4_rules = [], []
    for parsed_rule in grouped_rules:
        ipv4_rules, ivp6_rules = _rule_to_P4_table_match(parsed_rule)

        ipv4_P4_rules.extend(ipv4_rules)
        ipv6_P4_rules.extend(ivp6_rules)
    return ipv4_P4_rules, ipv6_P4_rules

def _rule_to_P4_table_match(grouped_rule):
    proto = grouped_rule.header.get('proto')
    src_ip_list = grouped_rule.header.get('source')
    src_port_list = grouped_rule.header.get('src_port')
    dst_ip_list = grouped_rule.header.get('destination')
    dst_port_list = grouped_rule.header.get('dst_port')

    if proto not in PROTO_MAPPING:
        print("No mapping for proto {}".format(proto))
        return [], []

    ipv4_flat_P4_rules, ipv6_flat_P4_rules = [], []
    for src_ip in src_ip_list:
        for src_port in src_port_list:
            for dst_ip in dst_ip_list:
                src_network = _convert_address_to_network(src_ip[0])
                dst_network= _convert_address_to_network(dst_ip[0])

                if type(src_network) != type(dst_network):
                    print("IPs in different version")
                    continue
                
                for dst_port in dst_port_list:
                    P4_rule_match = _create_P4_table_match(proto, src_network, src_port[0], dst_network, dst_port[0], grouped_rule.flags)
                    P4_rule = P4AggregatedMatch(P4_rule_match, grouped_rule.priority_list, grouped_rule.sid_rev_list)

                    if isinstance(ip_network(src_network), IPv4Network):
                        ipv4_flat_P4_rules.append(P4_rule)
                    else:
                        ipv6_flat_P4_rules.append(P4_rule)

    return ipv4_flat_P4_rules, ipv6_flat_P4_rules

def _convert_address_to_network(ip):
    if "/" not in ip:
        if ":" in ip:
            ip += "/128"
        else:
            ip += "/32"

    return ip_network(ip)

# Converts Snort rule header values to P4 table entries
def _create_P4_table_match(proto, src_network, src_port, dst_network, dst_port, flags):
    flags, flags_mask = _convert_flags_to_ternary(flags)

    p4_match_rule = P4Match()
    p4_match_rule.proto = PROTO_MAPPING.get(proto, None)

    p4_match_rule.src_network = src_network
    p4_match_rule.src_port = src_port

    p4_match_rule.dst_network = dst_network
    p4_match_rule.dst_port= dst_port

    p4_match_rule.flags = flags
    p4_match_rule.flags_mask = flags_mask

    return p4_match_rule


# Not supported
#     + - ALL flag, match on all specified flags plus any others
#     * - ANY flag, match on any of the specified flags
#     ! - NOT flag, match if the specified flags aren't set in the packet
def _convert_flags_to_ternary(flags_input, rule=None):
    supported_flag_values = {
        'F': 0x01,
        'S': 0x02,
        'R': 0x04,
        'P': 0x08,
        'A': 0x10,
        'U': 0x20,
        '2': 0x40,
        '1': 0x80,
    }

    flags = list(''.join(flags_input).replace(' ', ''))

    # If no flag set, allow any value
    if len(flags) == 0:
        return (0x00, 0x00)
    
    # Test for not supported characters
    invalid_flags = [invalid_flag for invalid_flag in flags
                     if invalid_flag not in supported_flag_values]

    if len(invalid_flags) != 0:
        print("Not supported flags {} found in {} from {} - {}".format(invalid_flags, flags, flags_input, rule))
        return (0x00, 0x00)

    result_value = 0
    for flag in flags:
        flag_value = supported_flag_values[flag]
        result_value += flag_value

    return (result_value, 0xff)


# Deduplicates p4 table entries with same match. Save each duplicate rule's priority and sid/rev 
def dedup_table_matches(rules):
    deduped_p4_rules = {}
    for rule in rules:
        rule_match = rule.match.to_string()
       
        if rule_match not in deduped_p4_rules:
            deduped_p4_rules[rule_match] = P4AggregatedMatch(rule.match, [], [])
        
        deduped_p4_rules[rule_match].priority_list.extend(rule.priority_list)
        deduped_p4_rules[rule_match].sid_rev_list.extend(rule.sid_rev_list)

    return list(deduped_p4_rules.values())
   

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

# Is rule1 within rule2?
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

    if not r1_match.src_network.subnet_of(r2_match.src_network):
        return False

    if not r1_match.dst_network.subnet_of(r2_match.dst_network):
        return False

    if not (r1_match.flags == r2_match.flags and \
            r1_match.flags_mask == r2_match.flags_mask):
        return False

    return True

def _get_port_range_start_end(port):
    if isinstance(port, range):
        return port.start, port.stop-1
    else:
        return int(port), int(port)


def create_table_entries(rules, table_name, output_port_param='1'):
    count = 0
    sids = []
    rules_qnt = []

    table_entries = []
    for rule in rules:
        count += 1
        table_entry = P4TableEntry(table=table_name,
                                       action='redirect',
                                       params=[output_port_param],
                                       priority=rule.min_priority(),
                                       agg_match=rule)
        
        table_entries.append(table_entry)

        sids.extend(rule.sids())
        rules_qnt.append(len(rule.sids()))

    return table_entries, sids, rules_qnt

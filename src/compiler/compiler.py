### Main file that compiles a Snort rule file according to the snort.conf and classification.conf to P4 table entries
# Args: config path, rules_path
#       - config_path: path to the configuration files
#       - rules_path: path to a single rule file or to a directory containing multiple rule files


## Standart and 3rd-party imports
import sys
import copy
from datetime import datetime
from binascii import hexlify
from socket import inet_aton
from ipaddress import ip_network, ip_address, IPv4Network

## Local imports
from snort_config_parser import SnortConfiguration
from rules_parser import get_rules, rules_to_sid_rev_map
from rule_statistics import RuleStatistics
from P4_related_classes import *
from rule_related_classes import *

# from utils import convert_ip_network_to_hex
# from port_mask import mask_range

MIN_PORT = 0
MAX_PORT = 65535


PROTO_MAPPING = {'icmp': 1, 'ip': 4, 'tcp': 6, 'udp': 17}

def main(config_path, rules_path):
    config = SnortConfiguration(snort_version=2, configuration_dir=config_path)
    ignored_rule_files = []
   
    print("Getting and parsing rules.....")
    print("Splitting bidirectional rules...")
    original_rules, fixed_bidirectional_rules = get_rules(rules_path, ignored_rule_files, config) # Get all rules from multiple files or just one
    # stats = RuleStatistics(original_rules, config)
    # stats.print_all()
    # rules_sid_rev_map = rules_to_sid_rev_map(rules)
    
    print("Deduplication of rules")
    deduped_rules = dedup_rules(fixed_bidirectional_rules, config)

    print("Adjusting rules. Replacing variables,grouping ports into ranges and adjsuting negated port rules")
    modified_rules = adjust_rules(deduped_rules, config) # Currently negated IPs are not supported
   

    print("Adjusting negated")
    print("Converting parsed rules to P4 table match")
    ipv4_p4_rules, ipv6_p4_rules = convert_rules_to_P4_table_match(modified_rules, config)
    

    print("Deduplication of P4 rules")
    deduped_ipv4_p4_rules = dedup_P4_rules(ipv4_p4_rules)
    deduped_ipv6_p4_rules = dedup_P4_rules(ipv6_p4_rules)
    #p4id_rules = sum([compile_p4id_ternary_range_size(rule) for rule in p4_rules_dedup])
    # Step 7) Reduce rules

    # p4_rules_reduced = reduce_rules_from_deduped(p4_rules_dedup)
    # p4id_rules_reduced = sum([compile_p4id_ternary_range_size(rule) for rule in p4_rules_reduced])

    print("Total original rules: {}".format(len(original_rules)))
    print("Total rules after fixing bidirectional rules: {}".format(len(fixed_bidirectional_rules)))
    print("Total processed rules dedup: {}".format(len(deduped_rules)))
    print("Total processed p4 rules: {}".format(len(ipv4_p4_rules)+len(ipv6_p4_rules)))
    print("Total processed p4 rules after deduping: {}".format(len(deduped_ipv4_p4_rules)+len(deduped_ipv6_p4_rules)))

    # print("Total processed p4 rules dedup p4id: {}".format(p4id_rules))
    # print("Total processed p4 rules reduced: {}".format(len(p4_rules_reduced)))
    # print("Total processed p4 rules reduced p4id: {}".format(p4id_rules_reduced))

    '''
    for i in range(len(rules)):
        if rules[i].header.get('proto') == 'udp':
            print(i)
            print(rules[i].header.values())
            print(transformed_rules[i].header.values())
            print(transformed_rules_grouped[i].header.values())
    '''

    print("Generating rules")
    # count = 0
    # sids = []
    # rules_qnt = []

    # for rule in p4_rules_dedup:
    #     output_port_param = '1'
    #     compiled_rule = P4CompiledRule(table='ids',
    #                                    action='redirect',
    #                                    params=[output_port_param],
    #                                    priority=rule.min_priority(),
    #                                    match=rule.match)
    #     # print("{}".format(compiled_rule.to_rule_string()))
    #     # print("[{}] {}".format(len(rule.sids()), compiled_rule.to_rule_string()))

    print("*" * 80)
    print("*" * 80)
    print("*" * 80)

    # for rule in p4_rules_reduced:
    #     count += 1
    #     output_port_param = '1'
    #     compiled_rule = P4CompiledRule(table='ids',
    #                                    action='redirect',
    #                                    params=[output_port_param],
    #                                    priority=rule.min_priority(),
    #                                    match=rule.match)
    #     sids.extend(rule.sids())
    #     rules_qnt.append(len(rule.sids()))
    #     # print("{}".format(compiled_rule.to_rule_string()))
    #     # print("[{}] {}".format(len(rule.sids()), compiled_rule.to_rule_string()))
    #     print("[{}] {}".format(rule.sids(), compiled_rule.to_rule_string()))

    # print()
    # print("Generating snort result")
    # unique_sids = list(set(sids))
    # print(f'Min: {min(rules_qnt)}')
    # print(f'Max: {max(rules_qnt)}')
    # from collections import Counter

    # print(f'Distribution: {sorted(list(set(rules_qnt)))}')
    # print(f'Distribution Counter: {Counter(rules_qnt)}')
    # print(f'Unique rules count: {len(unique_sids)}')
    # print(f'Unique rules: {unique_sids}')
    # print()

    # #for sid_rev in unique_sids:
    #     #print(rules_sid_rev_map[sid_rev].rule)

    # p4_rule_list_dict = [p4_rule.to_dict() for p4_rule in p4_rules_reduced]

    # import json
    # print(json.dumps(p4_rule_list_dict))


# Deduplicate signature rules with same match. Save each duplicate rule's priority and sid/rev 
def dedup_rules(p4_rules, config):
    deduped_rules = {}
    for rule in p4_rules:
        rule_id = rule.rule_id()
       
        if rule_id not in deduped_rules:
            deduped_rules[rule_id] = AggregatedRule(header=rule.header, flags=get_simple_option_value("flags", rule.options, []), \
                                                            priority_list=[], sid_rev_list=[])

        sid = get_simple_option_value("sid", rule.options)
        rev = get_simple_option_value("rev", rule.options)
        sid_rev_string = f'{sid}/{rev}'

        classtype = get_simple_option_value("classtype", rule.options)
        priority = config.classification_priority.get(classtype)
        
        deduped_rules[rule_id].priority_list.append(priority)
        deduped_rules[rule_id].sid_rev_list.append(sid_rev_string)

    return deduped_rules.values()


# Replace system variables, modify negated ports and group ports
def adjust_rules(deduped_rules, config):
    modified_rules = []
    for rule in deduped_rules:
        copied_header = copy.deepcopy(rule.header)
       
        copied_header['source'] = replace_system_variables(copied_header['source'],  config.ip_addresses)
        copied_header['src_port'] = replace_system_variables(copied_header['src_port'],  config.ports)
        copied_header['destination'] = replace_system_variables(copied_header['destination'], config.ip_addresses)
        copied_header['dst_port'] = replace_system_variables(copied_header['dst_port'],  config.ports)

        if(IP_negated(copied_header["source"]) or IP_negated(copied_header["destination"])):
            continue
    
        copied_header["src_port"] = modify_negated_ports(copied_header["src_port"])
        copied_header["dst_port"] = modify_negated_ports(copied_header["dst_port"])

        copied_header['src_port'] = group_ports_into_ranges(copied_header['src_port'])
        copied_header['dst_port'] = group_ports_into_ranges(copied_header['dst_port'])

        modified_rules.append(AggregatedRule(copied_header, rule.flags, rule.priority_list, rule.sid_rev_list))

    return modified_rules

# Substitute system variables for the real values in the config file and group ports into range
def replace_system_variables(header_field, config_variables):
    var_sub_results = []
    for value, bool_ in header_field:
        if isinstance(value, str) and "$" in value :
            key_temp = value.replace('$', '')
            variable_values = copy.deepcopy(config_variables.get(key_temp, "ERROR"))

            if not bool_:
                for index, (variable_value, variable_value_bool) in enumerate(variable_values):
                    variable_values[index] = (variable_value, bool(~(bool_ ^ variable_value_bool)+2))
            
            var_sub_results.extend(variable_values)
        else:
            var_sub_results.append((value, bool_))

    return var_sub_results
           
# Groups ports into ranges. Assumes no intersecting range value and duplicates. Sill simple
def group_ports_into_ranges(ports):
    count = 0
    initial_port = -1
    grouped_ports = []
    if len(ports) == 1:
        return ports

    sorted_ports = sorted(ports, key=lambda x: (int(x[0].start) if isinstance(x[0], range) else int(x[0])))
    for index, item in enumerate(sorted_ports):
        if isinstance(item[0], range):
            grouped_ports.append(item)
            continue

        if count == 0:
            initial_port = item[0]
            bool_ = item[1]

        try:
            next_tuple= sorted_ports[index+1] 
            if isinstance(next_tuple[0], range):
                next_tuple= (-1, False)
        except Exception as e:
            next_tuple= (-1, False)

        if int(item[0]) == int(next_tuple[0]) - 1 and item[1]==next_tuple[1]:
            count+=1
        else:
            if count == 0:
                grouped_ports.append((initial_port, bool_))
                continue
            
            grouped_ports.append((range(int(initial_port), int(initial_port)+count), bool_))
            count = 0
            initial_port = -1
    return grouped_ports

# Checks if an IP list has a negated entry
def IP_negated(ip_list):
    for ip in ip_list:
        if ip[1] == False:
            print("Negated IPs are not supported ", ip)
            return True

    return False

# Exchange the negated ports by their positive counterparts e.g., !10 == (range(0, 10), range(11, 65535)) 
def modify_negated_ports(ports):
    new_port_list = []
    for port in ports:
        if not port[1]:
            if isinstance(port[0], range):
                new_port_list.append((range(MIN_PORT, port[0].start), True))
                new_port_list.append((range(port[0].stop, MAX_PORT+1), True))
            else:
                new_port_list.append((range(MIN_PORT, int(port[0])), True))
                new_port_list.append((range(int(port[0])+1, MAX_PORT+1), True))
        else:
            new_port_list.append(port)

    return new_port_list


# Flattens snort rules to multiple p4 table entries
def convert_rules_to_P4_table_match(grouped_rules, config):
    ipv4_P4_rules, ipv6_P4_rules = [], []
    for parsed_rule in grouped_rules:
        ipv4_rules, ivp6_rules = rule_to_P4_table_match(parsed_rule)

        ipv4_P4_rules.extend(ipv4_rules)
        ipv6_P4_rules.extend(ivp6_rules)
    return ipv4_P4_rules, ipv6_P4_rules

def rule_to_P4_table_match(grouped_rule):
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
                src_network = (convert_address_to_network(src_ip[0]), src_ip[1])
                dst_network= (convert_address_to_network(dst_ip[0]), dst_ip[1])

                if type(ip_network(src_network[0])) != type(ip_network(dst_network[0])):
                    continue
                
                for dst_port in dst_port_list:
                    P4_rule_match = create_P4_table_match(proto, src_network, src_port, dst_network, dst_port, grouped_rule.flags)
                    P4_rule = P4MatchAggregatedRule(P4_rule_match, grouped_rule.priority_list, grouped_rule.sid_rev_list)

                    if isinstance(ip_network(src_network[0]), IPv4Network):
                        ipv4_flat_P4_rules.append(P4_rule)
                    else:
                        ipv6_flat_P4_rules.append(P4_rule)

    return ipv4_flat_P4_rules, ipv6_flat_P4_rules

# Returns value of key in rule options. Option value format: [(option_index, [option_index_values, ...]), ...]
def get_simple_option_value(key, options, default="ERROR"):
    try:
        return options[key][0][1][0]
    except Exception as e:
        #print("Error when searching for key {} in rule options \n Returning: {}".format(key, default))
        return default

# Converts Snort rule header values to P4 table entries
def create_P4_table_match(proto, src_network, src_port, dst_network, dst_port, flags):
    flags, flags_mask = convert_flags_to_ternary(flags)

    p4_match_rule = P4CompiledMatchRule()
    p4_match_rule.proto = PROTO_MAPPING.get(proto, None)

    # p4_match_rule.header_value_bool["src_addr"] = src_network
    # p4_match_rule.header_value_bool["src_port"] = src_port[1] # (value, bool)
    # p4_match_rule.header_value_bool["dst_addr"] = dst_network
    # p4_match_rule.header_value_bool["dst_port"] = dst_port[1]

    p4_match_rule.src_network = src_network
    p4_match_rule.src_port = src_port[0]

    p4_match_rule.dst_network = dst_network
    p4_match_rule.dst_port= dst_port[0]

    p4_match_rule.flags = flags
    p4_match_rule.flags_mask = flags_mask

    return p4_match_rule

def convert_address_to_network(ip):
    if "/" not in ip:
        if ":" in ip:
            ip += "/128"
        else:
            ip += "/32"

    return ip

# Not supported
#     + - ALL flag, match on all specified flags plus any others
#     * - ANY flag, match on any of the specified flags
#     ! - NOT flag, match if the specified flags aren't set in the packet
def convert_flags_to_ternary(flags_input, rule=None):
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


# Deduplicate p4 table entries with same match. Save each duplicate rule's priority and sid/rev 
def dedup_P4_rules(p4_rules):
    deduped_p4_rules = {}
    for rule in p4_rules:
        rule_match = rule.match.to_string()
       
        if rule_match not in deduped_p4_rules:
            deduped_p4_rules[rule_match] = P4MatchAggregatedRule(rule.match, [], [])
        
        deduped_p4_rules[rule_match].priority_list.extend(rule.priority_list)
        deduped_p4_rules[rule_match].sid_rev_list.extend(rule.sid_rev_list)

    return deduped_p4_rules.values()



def is_rule_within(rule1, rule2):
    r1_match = rule1.match
    r2_match = rule2.match

    if r1_match.proto != r2_match.proto:
        return False

    r1_src_port_end = 0xFFFF if r1_match.src_port_end == -1 else r1_match.src_port_end
    r2_src_port_end = 0xFFFF if r2_match.src_port_end == -1 else r2_match.src_port_end

    if not (r1_match.src_port_start >= r2_match.src_port_start and \
            r1_src_port_end <= r2_src_port_end):
        return False

    r1_dst_port_end = 0xFFFF if r1_match.dst_port_end == -1 else r1_match.dst_port_end
    r2_dst_port_end = 0xFFFF if r2_match.dst_port_end == -1 else r2_match.dst_port_end
    if not (r1_match.dst_port_start >= r2_match.dst_port_start and \
            r1_dst_port_end <= r2_dst_port_end):
        return False

    if r1_match.src_network.compare_networks(r2_match.src_network) == -1:
        return False

    if r1_match.dst_network.compare_networks(r2_match.dst_network) == -1:
        return False

    if not (r1_match.flags == r2_match.flags and \
            r1_match.flags_mask == r2_match.flags_mask):
        return False

    return True


def reduce_rules_from_deduped(rules):
    rules_list = []
    rules_dict = {}
    for rule in rules:
        rules_list.append(rule)
        rules_dict[rule.match.to_string()] = rule

    while (len(rules_list) > 0):
        rule = rules_list.pop()
        for rule_target in rules_list:
            if rule.match.to_string() in rules_dict and rule_target.match.to_string() in rules_dict:
                if is_rule_within(rule, rule_target):
                    rules_dict[rule_target.match.to_string()].sid_list.extend(rule.sid_rev_list)
                    rules_dict[rule_target.match.to_string()].priority_list.extend(rule.priority_list)
                    
                    del rules_dict[rule.match.to_string()]
                elif is_rule_within(rule_target, rule):
                    rules_dict[rule.match.to_string()].sid_list.extend(rule_target.sid_rev_list)
                    rules_dict[rule.match.to_string()].priority_list.extend(rule_target.priority_list)
                    
                    del rules_dict[rule_target.match.to_string()]
            elif rule.match.to_string() not in rules_dict:
                break

    return rules_dict.values()



def compile_p4id_ternary_range_size(rule):
    src_size = mask_range(rule.match.src_port_start, rule.match.src_port_end)
    dst_size = mask_range(rule.match.dst_port_start, rule.match.dst_port_end)
    return len(src_size) * len(dst_size)


if __name__ == '__main__':
    main(config_path=sys.argv[1], rules_path=sys.argv[2])

   

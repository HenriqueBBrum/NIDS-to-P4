### Main file that compiles a Snort rule file according to the snort.conf and classification.conf to P4 table entries

## Standart and 3rd-party imports
import sys
import copy
import gc
from datetime import datetime

## Local imports
from snort_config_parser import SnortConfiguration
from rules_parser import get_rules, rules_to_sid_rev_map
from rule_statistics import RuleStatistics
# from utils import convert_ip_network_to_hex
# from models import *
# from port_mask import mask_range

# Args: config path, rules_path
#       - config_path: path to the configuration files
#       - rules_path: path to a single rule file or to a directory containing multiple rule files

def main(config_path, rules_path):
    config = SnortConfiguration(snort_version=2, configuration_dir=config_path)
    ignored_rule_files = []
    print("Getting and parsing rules.....")
    rules = get_rules(rules_path, ignored_rule_files) # Get all rules from multiple files or just one

    # stats = RuleStatistics(rules, config)
    # stats.print_all()
    # rules_sid_rev_map = rules_to_sid_rev_map(rules)

    print("Adjusting rules. Replacing variables and grouping ports into ranges.....")
    new_rules = update_rules_ip_and_ports(rules, config)
  
    # for rule in new_rules:
    #     print(rule.header["src_port"])
    print("Converting parsed rules to P4 table entries")
    p4_rules = convert_parsed_rules_to_P4(new_rules, config)
    # # Step 6) Deduplicate rules
    # p4_rules_dedup = to_p4_match_dedupped_rules(p4_rules)
    # p4id_rules = sum([compile_p4id_ternary_range_size(rule) for rule in p4_rules_dedup])
    # # Step 7) Reduce rules

    # p4_rules_reduced = reduce_rules_from_deduped(p4_rules_dedup)
    # p4id_rules_reduced = sum([compile_p4id_ternary_range_size(rule) for rule in p4_rules_reduced])

    # print("Total processed rules: {}".format(len(rules)))
    # print("Total processed valid rules: {}".format(len(transformed_rules_filtered)))
    # print("Total processed p4 rules: {}".format(len(p4_rules)))
    # print("Total processed p4 rules dedup: {}".format(len(p4_rules_dedup)))
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


# For each rule update the IPs and port variables. Also groups values if the header field is src_port or dst_port
def update_rules_ip_and_ports(rules, config):
    rules_copy = copy.deepcopy(rules)

    for rule in rules_copy:
        rule.header['source'] = _update_rule_ip_and_ports(rule.header['source'],  config.ip_addresses, False)
        rule.header['src_port'] = _update_rule_ip_and_ports(rule.header['src_port'], config.ports, True)
        rule.header['destination'] = _update_rule_ip_and_ports(rule.header['destination'], config.ip_addresses, False)
        rule.header['dst_port'] = _update_rule_ip_and_ports(rule.header['dst_port'], config.ports, True)
    return rules_copy


# Substitute system variables for the real values in the config file and group ports into range
def _update_rule_ip_and_ports(header_field, config_variables, is_port):
    var_sub_results = []
    grouped_result = []

    for value, bool_ in header_field:
        if isinstance(value, str) and "$" in value :
            key_temp = value.replace('$', '')
            variable_values = config_variables.get(key_temp, "ERROR")
            if not bool_:
                for variable_value, variable_value_bool in variable_values:
                    variable_values[variable_value] =  bool(~(bool_ ^ variable_value_bool)+2)
            
            var_sub_results.extend(variable_values)
        else:
            var_sub_results.append((value, bool_))
    
    if is_port:
        grouped_result = group_ports_into_ranges(var_sub_results)
    else:
        grouped_result = var_sub_results
           
    return grouped_result

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


# 
def convert_parsed_rules_to_P4(parsed_rules, config):
    rules = []
    for parsed_rule in parsed_rules:
        P4_rules = parsed_rule_to_P4(parsed_rule, config)
        rules.extend(P4_rules)

    return rules



def parsed_rule_to_P4(parsed_rule, config):
    proto = parsed_rule.header.get('proto')
    src_ip_list = parsed_rule.header.get('source')
    src_port_list = parsed_rule.header.get('src_port')
    dst_ip_list = parsed_rule.header.get('destination')
    dst_port_list = parsed_rule.header.get('dst_port')

    flags = []
    pŕint(parsed_rule.options)
    for key, value in parsed_rule.options.values():
        if key == 'flags':
            flags = value
            print(parsed_rule.options)
            exit()

            break


    flat_p4_rules = []
    # for src in src_list:
    #     for src_port_range in src_port_range_list:
    #         for dst in dst_list:
    #             if "." not in dst:
    #                 print(parsed_rule.header.values())
    #                 exit(-1)
    #             for dst_port_range in dst_port_range_list:
    #                 sid = get_option_value(parsed_rule.options, 'sid', "0")[0]
    #                 rev = get_option_value(parsed_rule.options, 'rev', "0")[0]
    #                 classtype = get_option_value(parsed_rule.options, 'classtype', "unknown")[0]
    #                 priority = config.classifications.get(classtype).get('priority')
    #                 p4_rule_match = to_p4_match_rule(proto, src_ip_list, src_port_list, dst, dst_port_range, flags)
    #                 p4_rule = P4CompiledIDSMatchRule(match=p4_rule_match, priority=priority, sid=sid, rev=rev)
    #                 flat_p4_rules.append(p4_rule)
    return flat_p4_rules



def to_p4_match_rule(proto, src, src_port_range, dst, dst_port_range, flags):
    proto_mapping = {'icmp': 1, 'ip': 4, 'tcp': 6, 'udp': 17}
    # Convert
    if proto not in proto_mapping:
        print("No mapping for proto {}".format(proto))
        exit(-1)

    src_network, src_address, src_mask = convert_ip_network_to_hex(src)
    dst_network, dst_address, dst_mask = convert_ip_network_to_hex(dst)
    src_port_start, src_port_end = src_port_range
    dst_port_start, dst_port_end = dst_port_range

    flags, flags_mask = convert_flags_to_ternary(flags)

    p4_match_rule = P4CompiledMatchRule()
    p4_match_rule.proto = proto_mapping.get(proto, None)

    p4_match_rule.src_network = src_network
    p4_match_rule.src_addr = src_address
    p4_match_rule.src_addr_mask = src_mask

    p4_match_rule.dst_network = dst_network
    p4_match_rule.dst_addr = dst_address
    p4_match_rule.dst_addr_mask = dst_mask

    p4_match_rule.src_port_start = src_port_start
    p4_match_rule.src_port_end = src_port_end
    p4_match_rule.dst_port_start = dst_port_start
    p4_match_rule.dst_port_end = dst_port_end

    p4_match_rule.flags = flags
    p4_match_rule.flags_mask = flags_mask

    return p4_match_rule

# Not supported
#     + - ALL flag, match on all specified flags plus any others
#     * - ANY flag, match on any of the specified flags
#     ! - NOT flag, match if the specified flags aren't set in the packet
def convert_flags_to_ternary(flags_input, rule=None):
    flags_values_dict = {
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
    supported_flag_values = flags_values_dict.keys()
    invalid_flags = [invalid_flag for invalid_flag in flags
                     if invalid_flag not in supported_flag_values]

    if len(invalid_flags) != 0:
        print("Not supported flags {} found in {} from {} - {}".format(invalid_flags, flags, flags_input, rule))
        return (0x00, 0x00)

    result_value = 0
    for flag in flags:
        flag_value = flags_values_dict[flag]
        result_value += flag_value

    return (result_value, 0xff)

















def to_p4_match_dedupped_rules(ids_rules):
    dedup_ids_rules = {}
    # Aggregate
    for rule in ids_rules:
        rule_match = rule.match.to_match_string()
        if rule_match not in dedup_ids_rules:
            dedup_ids_rules[rule_match] = P4MatchAggregatedRule(match=rule.match, priority_list=[], sid_list=[])
        dedup_ids_rules[rule_match].priority_list.append(rule.priority)
        dedup_ids_rules[rule_match].sid_list.append(rule.to_sid_rev_string())

    return dedup_ids_rules.values()





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
        rules_dict[rule.match.to_match_string()] = rule

    while (len(rules_list) > 0):
        rule = rules_list.pop()
        for rule_target in rules_list:
            if rule.match.to_match_string() in rules_dict and rule_target.match.to_match_string() in rules_dict:
                if is_rule_within(rule, rule_target):
                    # Update rule target
                    rules_dict[rule_target.match.to_match_string()].sid_list.extend(rule.sid_list)
                    rules_dict[rule_target.match.to_match_string()].priority_list.extend(rule.priority_list)
                    if rule.match.to_match_string() in rules_dict:
                        del rules_dict[rule.match.to_match_string()]
                elif is_rule_within(rule_target, rule):
                    # Update rule
                    rules_dict[rule.match.to_match_string()].sid_list.extend(rule_target.sid_list)
                    rules_dict[rule.match.to_match_string()].priority_list.extend(rule_target.priority_list)
                    if rule_target.match.to_match_string() in rules_dict:
                        del rules_dict[rule_target.match.to_match_string()]

    return rules_dict.values()







def compile_p4id_ternary_range_size(rule):
    src_size = mask_range(rule.match.src_port_start, rule.match.src_port_end)
    dst_size = mask_range(rule.match.dst_port_start, rule.match.dst_port_end)
    return len(src_size) * len(dst_size)


if __name__ == '__main__':
    main(config_path=sys.argv[1], rules_path=sys.argv[2])

   

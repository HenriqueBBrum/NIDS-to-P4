### Main file that compiles a Snort rule file according to the snort.conf and classification.conf to P4 table entries

## Standart and 3rd-party imports
import sys
import copy
import gc
import time


## Local imports
from snort_config_parser import SnortConfiguration
from rules_parser import get_rules
# from rule_stats import RuleStatistics
# from utils import convert_ip_network_to_hex
# from models import *
# from port_mask import mask_range

# Args: config path, rules_path
#       - config_path: path to the configuration files
#       - rules_path: path to a single rule file or to a directory containing multiple rule files

def main(config_path, rules_path):
    config = SnortConfiguration(snort_version=2, configuration_dir=config_path)

    # exclude_sids = [254] ## Review why Kairo did this

    ignored_rule_files = []
    # # Step 1) Parse rules from files
    rules = get_rules(rules_path, ignored_rule_files) # Get all rules from multiple files or just one

    # print(len(rules))



    # stats = RuleStatistics(rules, config)
    # stats.print_all()


    # time.sleep(1000)


    # rules_sid_rev_map = rules_to_sid_rev_map(rules)
    # print(rules_sid_rev_map)
    # # Step 2) Transform rules based on config
    # transformed_rules = transform_rules_on_config(rules, config)
    # # Step 3) Filter transformed rules
    # transformed_rules_filtered = [rule for rule in transformed_rules
    #                               if rule.header.get("direction") == 'unidirectional' and
    #                               not is_wildcard(rule) and
    #                               not is_sid_excluded(rule, exclude_sids) and
    #                               not contains_ipv6(rule) and
    #                               get_rule_priority(rule) >= 1]
    

    # # Step 4) Transform rules
    # transformed_rules_grouped = transform_rules_on_port_range(transformed_rules_filtered, config)
    # # Step 5) Transform to P4 and group by range
    # p4_rules = grouped_rules_to_p4(config, transformed_rules_grouped)
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



def transform_rules_on_config(rules, config):
    rules_copy = copy.deepcopy(rules)

    def transform_value(include, value, vars, is_port):
        if include:
            if type(value) is list:
                result = []
                for v in value:
                    if type(v) is tuple:
                        include_new, value_new = v
                        result.extend(transform_value(include_new, value_new, vars, is_port))
                return result

            if "$" in value:
                key_var = value.replace('$', '')
                new_value = vars.get(key_var, "ERROR")
                return new_value

            if not is_port and value == "any":
                return ['0.0.0.0/0']

            if not is_port and type(value) is str:
                return [value]

            if is_port and value == "any":
                return [-1]

            if not is_port:
                return config.parse_ipvar(value)

            return config.parser_port_var(value)
        else:
            # TODO
            return config.parser_port_var(value)

    def set_rule_value(rule, key, vars, is_port):
        include, value = rule.header.get(key)
        rule.header[key] = transform_value(include, value, vars, is_port)

    for rule in rules_copy:
        set_rule_value(rule, 'source', config.ipaddress, False)
        set_rule_value(rule, 'src_port', config.ports, True)
        set_rule_value(rule, 'destination', config.ipaddress, False)
        set_rule_value(rule, 'dst_port', config.ports, True)

    return rules_copy


def transform_rules_on_port_range(rules, config):
    rules_copy = copy.deepcopy(rules)

    def set_rule_value(rule, key):
        values = rule.header.get(key)
        if type(values) == str:
            print(values)
            exit(0)
        rule.header[key] = config.group_ports(values)

    for rule in rules_copy:
        set_rule_value(rule, 'src_port')
        set_rule_value(rule, 'dst_port')

    return rules_copy


def grouped_rules_to_p4(config, grouped_rules):
    rules = []
    for rule in grouped_rules:
        p4_rules = parsed_rule_to_p4(config, rule)
        rules.extend(p4_rules)
        # gc.collect()
    return rules


def get_option_value(options, name, default):
    result = default
    for k, option in options.items():
        key, value = option
        if key == name:
            result = value
            break
    if type(result) is not list:
        return [result]
    return result


def parsed_rule_to_p4(config, parsed_rule):
    proto = parsed_rule.header.get('proto')
    src_list = parsed_rule.header.get('source')
    src_port_range_list = parsed_rule.header.get('src_port')
    dst_list = parsed_rule.header.get('destination')
    dst_port_range_list = parsed_rule.header.get('dst_port')
    flags = []
    for key, value in parsed_rule.options.values():
        if key == 'flags':
            flags = value
            break

    flat_p4_rules = []
    for src in src_list:
        for src_port_range in src_port_range_list:
            for dst in dst_list:
                if "." not in dst:
                    print(parsed_rule.header.values())
                    exit(-1)
                for dst_port_range in dst_port_range_list:
                    sid = get_option_value(parsed_rule.options, 'sid', "0")[0]
                    rev = get_option_value(parsed_rule.options, 'rev', "0")[0]
                    classtype = get_option_value(parsed_rule.options, 'classtype', "unknown")[0]
                    priority = config.classifications.get(classtype).get('priority')
                    p4_rule_match = to_p4_match_rule(proto, src, src_port_range, dst, dst_port_range, flags)
                    p4_rule = P4CompiledIDSMatchRule(match=p4_rule_match, priority=priority, sid=sid, rev=rev)
                    flat_p4_rules.append(p4_rule)
    return flat_p4_rules


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


def is_wildcard(rule, max_port=512):
    flag = None
    flag_mask = None
    for key, value in rule.options.values():
        if key == 'flags':
            flag, flag_mask = convert_flags_to_ternary(value, rule)
            break

    wildcard_ip = ['0.0.0.0/0']
    wildcard_port = [-1]
    src_port = rule.header.get('src_port')
    dst_port = rule.header.get('dst_port')

    if (src_port == wildcard_port and
        dst_port == wildcard_port) and \
            not flag:
        return True
    if (((src_port == wildcard_port and
          len(dst_port) > max_port)) or
        ((dst_port == wildcard_port and
          len(src_port) > max_port))) and \
            not flag:
        return True
    return False


def contains_ipv6(rule):
    src_list = rule.header.get('source')
    dst_list = rule.header.get('destination')

    for src in src_list:
        if ':' in src:
            return True
    for dst in dst_list:
        if ':' in dst:
            return True

    return False


def rules_to_sid_rev_map(parsed_rules):
    rules_map = {}
    for parsed_rule in parsed_rules:
        sid = get_option_value(parsed_rule.options, 'sid', "0")[0]
        rev = get_option_value(parsed_rule.options, 'rev', "0")[0]
        key = f'{sid}/{rev}'
        rules_map[key] = parsed_rule
    return rules_map


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


def is_sid_excluded(rule, excluded_sids):
    sid = int(get_option_value(rule.options, 'sid', "0")[0])
    return sid in excluded_sids


def get_rule_priority(parsed_rule):
    classtype = get_option_value(parsed_rule.options, 'classtype', "unknown")[0]
    return config.classifications.get(classtype).get('priority')



def compile_p4id_ternary_range_size(rule):
    src_size = mask_range(rule.match.src_port_start, rule.match.src_port_end)
    dst_size = mask_range(rule.match.dst_port_start, rule.match.dst_port_end)
    return len(src_size) * len(dst_size)


if __name__ == '__main__':
    main(config_path=sys.argv[1], rules_path=sys.argv[2])

   

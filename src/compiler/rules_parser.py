from os import listdir
from os.path import isfile, join
import copy

from snort_rule_parser.parser import Parser, Rule


# Returns a list of rules from one or multiple files
def get_rules(rules_path, ignored_rule_files, snort_config):
    files = []
    if isfile(rules_path):
        files =  [rules_path]
    else:
        for file in listdir(rules_path):
            file_full_path = join(rules_path, file)
            if isfile(file_full_path) and '.rules' in file and file not in ignored_rule_files:
                files.append(join(rules_path, file))

    original_rules, final_rules = [], []
    for rule_file in files:
        parsed_rules, modified_rules = __parse_rules(rule_file, snort_config)
        original_rules.extend(parsed_rules)
        final_rules.extend(modified_rules)
      
    return original_rules, final_rules

# Parse each rule from a rule file
def __parse_rules(rule_file, snort_config):
    parsed_rules, modified_rules = [], []
    with open(rule_file, 'r') as file:
        lines = file.readlines()
        for line in lines:
            if line.startswith("#") or len(line)<=1:
                continue
            parser = Parser()
            parsed_rule = parser.parse_rule(line)
            parsed_rules.append(parsed_rule)

            copied_rule = copy.deepcopy(parsed_rule)
            copied_rule.header['source'] = update_rule_ip_and_ports(copied_rule.header['source'],  snort_config.ip_addresses, False)
            copied_rule.header['src_port'] = update_rule_ip_and_ports(copied_rule.header['src_port'], snort_config.ports, True)
            copied_rule.header['destination'] = update_rule_ip_and_ports(copied_rule.header['destination'], snort_config.ip_addresses, False)
            copied_rule.header['dst_port'] = update_rule_ip_and_ports(copied_rule.header['dst_port'], snort_config.ports, True)

            if copied_rule.header.get("direction") == "bidirectional":
                copied_rule.header['direction'] = "unidirectional"

                swap_dir_rule = copy.deepcopy(copied_rule)
                swap_dir_rule.header['source'], swap_dir_rule.header['destination'] =  swap_dir_rule.header['destination'], swap_dir_rule.header['source']
                swap_dir_rule.header['src_port'], swap_dir_rule.header['dst_port'] =  swap_dir_rule.header['dst_port'], swap_dir_rule.header['src_port']

                modified_rules.append(copied_rule)
                modified_rules.append(swap_dir_rule)
            else:
                modified_rules.append(copied_rule)

    return parsed_rules, modified_rules

# Substitute system variables for the real values in the config file and group ports into range
def update_rule_ip_and_ports(header_field, config_variables, is_port):
    var_sub_results = []

    for value, bool_ in header_field:
        if isinstance(value, str) and "$" in value :
            key_temp = value.replace('$', '')
            variable_values = config_variables.get(key_temp, "ERROR")
            if not bool_:
                for index, (variable_value, variable_value_bool) in enumerate(variable_values):
                    variable_values[index] = (variable_value, bool(~(bool_ ^ variable_value_bool)+2))
            
            var_sub_results.extend(variable_values)
        else:
            var_sub_results.append((value, bool_))
    
    if is_port:
        return group_ports_into_ranges(var_sub_results)
    else:
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



# Return rules with unique sid/rev
def rules_to_sid_rev_map(parsed_rules):
    rules_map = {}
    for parsed_rule in parsed_rules:
        sid = parsed_rule.options.get('sid', "0")["value"][0]
        rev = parsed_rule.options.get('rev', "0")["value"][0]
        key = f'{sid}/{rev}'
        rules_map[key] = parsed_rule
    return rules_map
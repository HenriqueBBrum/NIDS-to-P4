from os import listdir
from os.path import isfile, join
import copy

from snort_rule_parser.parser import Parser, Rule


# Returns two list of rules from one or multiple files. 
# The first list contains the parsed rules similar as they apperead in the files but saving the values in dictionaries. 
# The second list contains adjusted bidirectional rules, with port groupping and with the IP and port variables exchanged with the real values.
def get_rules(rules_path, ignored_rule_files, snort_config):
    files = []
    if isfile(rules_path):
        files =  [rules_path]
    else:
        for file in listdir(rules_path):
            file_full_path = join(rules_path, file)
            if isfile(file_full_path) and '.rules' in file and file not in ignored_rule_files:
                files.append(join(rules_path, file))

    original_rules, modified_rules = [], []
    for rule_file in files:
        parsed_rules, adjusted_rules = __parse_rules(rule_file, snort_config)
        original_rules.extend(parsed_rules)
        modified_rules.extend(adjusted_rules)
      
    return original_rules, modified_rules

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
            if copied_rule.header.get("direction") == "bidirectional":
                copied_rule.header['direction'] = "unidirectional"

                swap_dir_rule = copy.deepcopy(copied_rule)
                swap_dir_rule.header['source'], swap_dir_rule.header['destination'] =  swap_dir_rule.header['destination'], swap_dir_rule.header['source']
                swap_dir_rule.header['src_port'], swap_dir_rule.header['dst_port'] =  swap_dir_rule.header['dst_port'], swap_dir_rule.header['src_port']

                copied_rule.header["source"][0][0]
              
                modified_rules.append(copied_rule)
                modified_rules.append(swap_dir_rule)
            else:
                modified_rules.append(copied_rule)

    return parsed_rules, modified_rules




# Return rules with unique sid/rev
def rules_to_sid_rev_map(parsed_rules):
    rules_map = {}
    for parsed_rule in parsed_rules:
        sid = parsed_rule.options.get('sid', "0")["value"][0]
        rev = parsed_rule.options.get('rev', "0")["value"][0]
        key = f'{sid}/{rev}'
        rules_map[key] = parsed_rule
    return rules_map
from os import listdir
from os.path import isfile, join

from snort_rule_parser.parser import Parser


# Returns a list of rules from one or multiple files
def get_rules(rules_path, ignored_rule_files):
    files = []
    if isfile(rules_path):
        files =  [rules_path]
    else:
        for file in listdir(rules_path):
            file_full_path = join(rules_path, file)
            if isfile(file_full_path) and '.rules' in file and file not in ignored_rule_files:
                files.append(join(rules_path, file))

    rules = []
    for rule_file in files:
        rules.extend(__parse_rules(rule_file))
      
    return rules

# Parse each rule from a rule file
def __parse_rules(rule_file):
    parsed_rules = []
    with open(rule_file, 'r') as file:
        lines = file.readlines()
        for line in lines:
            if line.startswith("#") or len(line)<=1:
                continue
            parser = Parser()
            parsed_rules.append(parser.parse_rule(line))

    return parsed_rules

# Return rules with unique sid/rev
def rules_to_sid_rev_map(parsed_rules):
    rules_map = {}
    for parsed_rule in parsed_rules:
        sid = parsed_rule.options.get('sid', "0")["value"][0]
        rev = parsed_rule.options.get('rev', "0")["value"][0]
        key = f'{sid}/{rev}'
        rules_map[key] = parsed_rule
    return rules_map

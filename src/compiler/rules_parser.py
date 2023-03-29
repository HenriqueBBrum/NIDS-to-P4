from os import listdir
from os.path import isfile, join

from snort_rule_parser.parser import Parser

# Returns a list of file or files depending if "rules_path" is a file or a directory
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
        rules.extend(read_rules(rule_file))
      
    return rules


def read_rules(rule_file):
    rules, parsed_rules = [], []
   
    with open(rule_file, 'r') as file:
        lines = file.readlines()
        for line in lines:
            if line.startswith("#") or len(line)<=1:
                continue

            # Does not make sense. Why would a commented out rule be used?
            # if filter_commented_rules:
            #     if rule.startswith('#'):
            #         continue


            # Wrong logic. Using this logic this rule would be removed even tough no negation syntax is used for either the ip or port fields:
            # 
            # alert tcp $EXTERNAL_NET any -> $TELNET_SERVERS 23 (msg:"MALWARE-BACKDOOR MISC Linux rootkit attempt"; flow:to_server,established; 
            # content:"wh00t!"; metadata:ruleset community; reference:url,attack.mitre.org/techniques/T1014; classtype:attempted-admin; sid:213; rev:9;)   
            # Review or simply remove this rule
            # if filter_negation:
            #     if '!' in rule:
            #         continue
            rule = Parser(line).header
            parsed_rules.append(rule)

            break

    return parsed_rules


# def is_rule(rule_line):
#     return 'alert' in str(rule_line) and len(rule_line) > 100 ## 100???


### What is the use for these functions?
# def get_keys(row):
#     return row.keys()

# def parse_port(value):
#     if "$" in value or ":" in value:
#         return value
#     return int(value)

# def parse_rules_from_multiple_files(rules_files, filter_commented_rules=False, filter_negation=True):
#     rules = []
#     for file in rules_files:
#         print(file)
#         file_rules = read_rules(file, filter_commented_rules, filter_negation)
#         rules.extend(file_rules)
#     return rules


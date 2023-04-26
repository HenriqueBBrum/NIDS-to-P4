### Main file that compiles a Snort rule file according to the snort.conf and classification.conf to P4 table entries
# Args: config path, rules_path
#       - config_path: path to the configuration files
#       - rules_path: path to a single rule file or to a directory containing multiple rule files


## Standard and 3rd-party imports
import sys
# from binascii import hexlify
# from socket import inet_aton
from datetime import datetime
from json import load
import random


## Local imports
from snort_config_parser import SnortConfiguration
from snort_rule_parser.rules_parser import get_rules, dedup_rules, adjust_rules
from snort_rule_parser.rule_statistics import RuleStatistics
from rules_to_P4 import rules_to_P4_table_match, dedup_table_matches, reduce_table_matches , create_table_entries 

# from utils import convert_ip_network_to_hex
# from port_mask import mask_range


def main(config_path, rules_path, compiler_goal_path, table_entries_file="src/p4/p4snort.config"):
    compiler_goal = parse_compiler_goal(compiler_goal_path)
    config = SnortConfiguration(snort_version=2, configuration_dir=config_path)

    print("*" * 80)
    print("*" * 80)
    print("*" * 26 + " SNORT RULES PARSING STAGE " + "*" * 27+ "\n\n")
    modified_rules = rule_parsing_stage(config, rules_path)

      
    print("\n\n"+"*" * 80)
    print("*" * 80)
    print("*" * 23 + " SNORT RULES TO P4 TABLE ENTRIES STAGE " + "*" * 23+ "\n\n")
    p4_ipv4_table_entries, p4_ipv6_table_entries = rule_to_P4_table_entry_stage(config, modified_rules)


    print("\n\n"+"*" * 80)
    print("*" * 80)
    print("*" * 20 + " PRIORITIZING AND SAVING TABLE ENTRIES " + "*" * 21+ "\n\n")
    combined_table_entries = p4_ipv4_table_entries + p4_ipv6_table_entries

    prioritized_table_entries = prioritize_table_entries(compiler_goal, combined_table_entries)
    save_table_entries(prioritized_table_entries, table_entries_file)
   
   

def parse_compiler_goal(compiler_goal_path):
    VALID_TARGET_PLATFORMS = {"bmv2"}
    VALID_TARGET_GOALS = {"max_severity", "max_rules", "random_rules"}

    with open(compiler_goal_path, 'r') as compiler_goal_file:
        compiler_goal = load(compiler_goal_file)

    if compiler_goal["table_size_limit"] < 1:
        raise Exception(f'Invalid table size: {compiler_goal["table_size_limit"]}')

    if compiler_goal["target_platform"].lower() not in VALID_TARGET_PLATFORMS:
        raise Exception(f'Target platform not supported: {compiler_goal["target_platform"]}')
    
    if compiler_goal["target_goal"].lower() not in VALID_TARGET_GOALS:
        raise Exception(f'Target GOAL not supported: {compiler_goal["target_goal"]}')

    return compiler_goal


def rule_parsing_stage(config, rules_path):
    ignored_rule_files = []

    print("---- Getting and parsing rules..... ----")
    print("---- Splitting bidirectional rules..... ----")
    original_rules, fixed_bidirectional_rules = get_rules(rules_path, ignored_rule_files) # Get all rules from multiple files or just one
    # stats = RuleStatistics(config, original_rules)
    # stats.print_all()
    
    print("---- Deduplication of rules..... ----")
    deduped_rules = dedup_rules(config, fixed_bidirectional_rules)

    print("---- Adjusting rules. Replacing variables,grouping ports into ranges and adjusting negated port rules..... ----")
    modified_rules = adjust_rules(config, deduped_rules) # Currently negated IPs are not supported

    print("\nResults:")
    print("Total original rules: {}".format(len(original_rules)))
    print("Total rules after fixing bidirectional rules: {}".format(len(fixed_bidirectional_rules)))
    print("Total processed rules dedup: {}".format(len(deduped_rules)))

    return modified_rules


def rule_to_P4_table_entry_stage(config, modified_rules):
    print("---- Converting parsed rules to P4 table matches ----")
    ipv4_p4_table_matches, ipv6_p4_table_matches = rules_to_P4_table_match(modified_rules, config)
    
    print("---- Deduplication of P4 table matches ----")
    deduped_ipv4_table_matches = dedup_table_matches(ipv4_p4_table_matches)
    deduped_ipv6_table_matches = dedup_table_matches(ipv6_p4_table_matches)
    
    #p4id_rules = sum([compile_p4id_ternary_range_size(rule) for rule in p4_rules_dedup])

    print("---- Reducing P4 rules ----")
    reduced_ipv4_table_matches = reduce_table_matches(deduped_ipv4_table_matches)
    reduced_ipv6_table_matches = reduce_table_matches(deduped_ipv6_table_matches)

    print("---- Generating table entries ----")
    p4_ipv4_table_entries, sids_ipv4, rules_qnt_ipv4 = create_table_entries(reduced_ipv4_table_matches, "ipv4_ids")
    p4_ipv6_table_entires, sids_ipv6, rules_qnt_ipv6 = create_table_entries(reduced_ipv6_table_matches, "ipv6_ids")

    sids = sids_ipv4 + sids_ipv6
    rules_qnt = rules_qnt_ipv4 + rules_qnt_ipv6

    print("Snort to P4 results: \n")
    print("Total processed p4 rules: {}".format(len(ipv4_p4_table_matches)+len(ipv6_p4_table_matches)))
    print("Total processed p4 rules after deduping: {}".format(len(deduped_ipv4_table_matches)+len(deduped_ipv6_table_matches)))
    # print("Total processed p4 rules dedup p4id: {}".format(p4id_rules))
    print("Total processed p4 rules reduced: {}".format(len(reduced_ipv4_table_matches)+len(reduced_ipv6_table_matches)))
    # print("Total processed p4 rules reduced p4id: {}".format(p4id_rules_reduced))
    # p4id_rules_reduced = sum([compile_p4id_ternary_range_size(rule) for rule in p4_rules_reduced])

    print()
    print("Sids results:")
    unique_sids = list(set(sids))
    print(f"Amt of sids: {len(sids)}")
    print(f'Min: {min(rules_qnt)}')
    print(f'Max: {max(rules_qnt)}')
    from collections import Counter

    print(f'Distribution: {sorted(list(set(rules_qnt)))}')
    print(f'Distribution Counter: {Counter(rules_qnt)}')
    print(f'Unique rules count: {len(unique_sids)}')

    return p4_ipv4_table_entries, p4_ipv6_table_entires



def prioritize_table_entries(compiler_goal, table_entries): 
    VALID_TARGET_GOALS = {"max_severity": max_severity, "max_rules": max_rules, "random_rules": random_rules}
    max_table_size = compiler_goal["table_size_limit"]
    try:  
        prioritized_rules = VALID_TARGET_GOALS[compiler_goal["target_goal"]](table_entries, max_table_size)
    except:
        raise Exception

    return prioritized_rules

def max_severity(table_entries, max_table_size):
    prioritized_rules = []
    capacity_limit = min(len(table_entries), max_table_size)

    # Prioritize rule based on the severity/priority
    sorted_table_entries_by_severity = sorted(table_entries, key=lambda entry: entry.priority, reverse=True)
    return sorted_table_entries_by_severity[0:capacity_limit]

def max_rules(table_entries, max_table_size):
    prioritized_rules = []
    capacity_limit = min(len(table_entries), max_table_size)

    # Prioritize rule based on the quantity of NIDS rules
    sorted_table_entries_by_rules_quantity = sorted(table_entries, key=lambda entry: len(entry.agg_match.sid_rev_list), reverse=True)
    return sorted_table_entries_by_rules_quantity[0:capacity_limit]

def random_rules(table_entries, max_table_size):
    prioritized_rules = []
    capacity_limit = min(len(table_entries), max_table_size)
    prioritized_rules = random.sample(table_entries, capacity_limit)
    return prioritized_rules


def save_table_entries(table_entries, filepath):
    with open(filepath, 'w') as file:
        for table_entry in table_entries:
            file.write(table_entry.to_string()+"\n")

# def compile_p4id_ternary_range_size(rule):
#     src_size = mask_range(rule.match.src_port_start, rule.match.src_port_end)
#     dst_size = mask_range(rule.match.dst_port_start, rule.match.dst_port_end)
#     return len(src_size) * len(dst_size)


if __name__ == '__main__':
    main(config_path=sys.argv[1], rules_path=sys.argv[2], compiler_goal_path=sys.argv[3])

   

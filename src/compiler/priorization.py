# from data.community import COMPILED_RULES_COMMUNITY
import random
import itertools

def max_total_rules(p4_agg_rules, max_table_size):
    #combinations = list()
    i = 0
    best_rules = []
    best_qnt = 0

    max_qnt_list = []
    for rule in p4_agg_rules:
        max_qnt_list.extend(rule['sid_list'])
    total = len(list(set(max_qnt_list)))

    for c in itertools.combinations(p4_agg_rules, max_table_size):
        i = i + 1
        rules = list(c)
        max_qnt_list = []
        for rule in rules:
            max_qnt_list.extend(rule['sid_list'])
        max_qnt = len(list(set(max_qnt_list)))
        if best_qnt < max_qnt:
            best_qnt = max_qnt
            best_rules = rules
            print(best_qnt)

        if max_qnt == total:
            best_qnt = max_qnt
            best_rules = rules
            break

    print(f'Combinations {i}')
    print(f'Best Qnt {best_qnt}')
    #print(best_qnt)
    return best_rules

# def analyse_histogram(rules):
#     rules_qnt = [len(list(set(rule['sid_list']))) for rule in rules]
#     print(f'Min: {min(rules_qnt)}')
#     print(f'Max: {max(rules_qnt)}')
#     from collections import Counter

#     print(f'Distribution: {sorted(list(set(rules_qnt)))}')
#     print(f'Distribution Counter: {Counter(rules_qnt)}')

#     max_priority_list = [min(rule['priority_list']) for rule in rules]
#     print(f'Total Risk Distribution Counter: {Counter(max_priority_list)}')
#     max_qnt_list = []
#     for rule in rules:
#         max_qnt_list.extend(rule['sid_list'])
#     max_qnt = len(list(set(max_qnt_list)))
#     print(f'Total rules qnt Distribution Counter: {max_qnt}')

#     prioritized_max_severity_rules = max_severity(rules, 512)
#     print(len(prioritized_max_severity_rules))
#     max_priority_list = [min(rule['priority_list']) for rule in prioritized_max_severity_rules]
#     print(f'Max Severity Risk Distribution Counter: {Counter(max_priority_list)}')
#     max_qnt_list = []
#     for rule in prioritized_max_severity_rules:
#         max_qnt_list.extend(rule['sid_list'])
#     max_qnt = len(list(set(max_qnt_list)))
#     print(f'Total rules qnt Distribution Counter: {max_qnt}')

#     prioritized_max_severity_rules = max_rules(rules, 512)
#     print(len(prioritized_max_severity_rules))
#     max_priority_list = [min(rule['priority_list']) for rule in prioritized_max_severity_rules]
#     print(f'Max rules Risk Distribution Counter: {Counter(max_priority_list)}')
#     max_qnt_list = []
#     for rule in prioritized_max_severity_rules:
#         max_qnt_list.extend(rule['sid_list'])
#     max_qnt = len(list(set(max_qnt_list)))
#     print(f'Total rules qnt Distribution Counter: {max_qnt}')

#     prioritized_max_severity_rules = random_rules(rules, 512)
#     print(len(prioritized_max_severity_rules))
#     max_priority_list = [min(rule['priority_list']) for rule in prioritized_max_severity_rules]
#     print(f'Random Severity Risk Distribution Counter: {Counter(max_priority_list)}')
#     max_qnt_list = []
#     for rule in prioritized_max_severity_rules:
#         max_qnt_list.extend(rule['sid_list'])
#     max_qnt = len(list(set(max_qnt_list)))
#     print(f'Total rules qnt Distribution Counter: {max_qnt}')

#     max_total_rules(rules, 512)

if __name__ == '__main__':
    print(len(COMPILED_RULES_COMMUNITY))

    analyse_histogram(COMPILED_RULES_COMMUNITY)

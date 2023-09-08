# Converting NIDS rules to P4 table entries

This repository contains a compiler that converts NIDS rules to P4 table entries. It receives three inputs: a configuration file containing IP variables and port variables, the folder or file containing the NIDS rules, and a configuration goal indicating the desired P4 target and the ordering of the rules. 

## How does it work?

This compiler converts signature rules from Open-source NIDS, such as Snort and Suricata, to P4 table entries. The steps done by this compiler are the following:

- Rules parsing -> This step is encharged with retrieving the NIDS signatures rules from a file or multiple files and saving them into data structures. For more information about Snort rules, go to this link [https://docs.snort.org/start/rules](https://docs.snort.org/start/rules)

- Rules adjusting -> After parsing the rules, they are adjusted according to the configuration file. For example, some NIDS rules might have `$HOME_NET` in the IP fields, and in this step, `$HOME_NET` is replaced by the real IPs. Other tasks in this step include grouping ports into ranges, adjusting rules with negated ports, and removing rules with negated IPs.

- Rule deduplication -> With the rules adjusted, duplicate rules are removed. A rule is considered a duplicate if another rule has the same protocol, source, direction, destination, and TCP flags (if the rule is TCP).

- Removing wildcard rules -> TCP or UDP rules with source and destination ports as wildcards and at least one IP field as wildcard.

- Converting rules to P4 table entries -> This step converts all rules into P4 table entries. A table entry comprises the protocol, source, destination, and TCP flags fields. A rule generates `source_IP\*source_port\*destination_IP\*destination_port` entries.

- Table entry deduplication -> With the table entries created, duplicate entries are removed. A table entry is considered a duplicate if another entry has all the same field values.

- Rule grouping (reducing) -> The final step groups entries that are encompassed by a more "general" entry. For example, suppose two entries have all the same fields, but the source port of entry A is 80, and table entry B is the range 10-100. In the grouping stage, entry A is removed from the final ruleset since any packet that might match entry A is already matched by entry B.

For more information, go to the `src/compiler.py` file and check the other files for more details.

## Usage guide

Clone this repo:

```
git clone
```

There are three supported signature datasets, `Snort 2&3 Community`, `Snort 2 Emerging Threats`, and `Snort 3 Registered`. After cloning the repo in a computer with Python 3 installed, run one of the following commands to generate your P4 table entries output file. The resulting P4 table entries file is saved in the `output` folder. 


To generate an output file with P4 table entries from the COMMUNITY rulesets:

```
make compiler.community
```
To generate an output file with P4 table entries from the EMERGING THREATS rulesets:

```
make compiler.emerging
```

To generate an output file with P4 table entries from the REGISTERED rulesets:

```
make compiler.registered
```


### Evaluate memory usage and time duration

To evaluate the memory usage, run the following command:

```
make compiler.memory_eval
```

By default, this command evaluates the compiler with the Snort 2&3 Community ruleset. To evaluate the memory usage with other rulesets, you need to run this commands informing the desired ruleset. For example, to run the memory usage evaluation for the Snort 2 Registered ruleset, the command is:

```
make compiler.memory_eval EVAL_RULES=etc/rules/snort2-emerging
```

To evaluate the runtime duration, run the following command:

```
time make compiler.community
```

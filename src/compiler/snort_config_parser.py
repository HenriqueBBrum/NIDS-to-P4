### This file contains a class that parsers the network variables defined by snort
##  Works for Snort 2.* configuration (future versions will inlcude Snort 3.* and SUricata)

import re

class SnortConfiguration():
    ports = {}
    ip_addresses = {}
    classification_priority = {}

    MIN_PORT = 0
    MAX_PORT = 65535

    

    def __init__(self, snort_version, configuration_dir):
        self.configuration_dir = configuration_dir
        self.snort_version = snort_version

        self.__parse()
    


    def __parse(self):
        if(self.snort_version == 2):
            snort_config_file= "{}/snort.conf".format(self.configuration_dir) 
            priority_classification_file = "{}/classification.config".format(self.configuration_dir)
            self.__parse_snort_config(snort_config_file)
            self.__parse_classification_priority(priority_classification_file)
        elif(self.snort_version == 3):
            snort_lua = "{}/snort.lua".format(self.configuration_dir) 
            snort_defaults_lua = "{}/snort_defaults.lua".format(self.configuration_dir) 



    # Translates the ip and port variables to their real values (e.g: $HOME_NET ->[10.0.0.1, 10.0.02, ...])
    # For more info, go to -> https://suricata.readthedocs.io/en/suricata-4.1.4/rules/intro.html#source-and-destination
    def __parse_snort_config(self, snort_config_file):
        with open(snort_config_file, 'r') as config_file:
            lines  = config_file.readlines()
            for line in lines:
                if("# Step #2:"in line): ## NETWORK SETTINGS ARE ONLY IN "STEP 1" FOR TYPICAL SNORT CONFIGURATION FILES
                    break
                if (line.startswith("ipvar")):
                    ipvar_line_elements = line.split(" ") # ipvar NAME IPs
                    name = ipvar_line_elements[1]
                    self.ip_addresses[name] = self.__parse_ips(ipvar_line_elements[2].rstrip('\n'))
                elif(line.startswith("portvar")):
                    portvar_line_elements = line.split(" ") # portvar NAME IPs
                    name = portvar_line_elements[1]
                    self.ports[name] = self.__parse_ports(portvar_line_elements[2].rstrip('\n'))



    ### TODO parse list with negated sublits(i.e. [![[],![]], [], ...])
    ### TODO validate input line
    ### TODO verify any inconsistencies, for example:(21, TRUE) and (22, True)
    def __parse_ips(self, raw_ips)  -> list :
        if raw_ips == "any":
            return [("0.0.0.0/0", True)]
        
        parsed_ips = []
        if raw_ips.startswith("["):
            raw_ips = raw_ips[1:-1]
            if("![" not in raw_ips):
                list_of_ips = re.sub(r'[\[\]]', '', raw_ips).split(",")
                for ips in list_of_ips:
                    parsed_ips.extend(self.__parse_ip(ips))
        elif raw_ips.startswith("!["):
            list_of_ips = self.__parse_ips(raw_ips[1:])
            for ip in list_of_ips:
                parsed_ips.append((ip[0], bool(~(False ^ ip[1])+2))) #xnor because !! = true
            return parsed_ips
        else:
            parsed_ips = self.__parse_ip(raw_ips)
        return parsed_ips   



    # Parses individual IPs. 
    # Obs: Variable inputs (e.g. $HOME_NET) even if they are a list, they are already parsed lists with no sublists and other vars. 
    def __parse_ip(self, raw_ip):
        if raw_ip.startswith("$"):
            return self.ip_addresses[raw_ip.replace('$', '')]
        elif raw_ip.startswith("!$"):
            list_of_ips = self.ip_addresses[raw_ip.replace("!$", '')]
            parsed_ips = []
            for ip in list_of_ips:
                parsed_ips.append((ip[0], bool(~(False ^ ip[1])+2))) #xnor because !! = true
            return parsed_ips
        else:
            bool_multiplier = True
            if(raw_ip.startswith("!")):
                raw_ip = raw_ip[1:]
                bool_multiplier = False
        return [(raw_ip, bool_multiplier)]



    ### TODO parse list with negated sublits(i.e. [![[],![]], [], ...])
    def __parse_ports(self, raw_ports):
        if raw_ports == "any":
            return [range(self.MIN_PORT, self.MAX_PORT)]
        
        parsed_ports = []
        if raw_ports.startswith("["):
            raw_ports = raw_ports[1:-1]
            if("![" not in raw_ports):
                list_of_ports = re.sub(r'[\[\]]', '', raw_ports).split(",")
                for port in list_of_ports:
                    parsed_ports.extend(self.__parse_port(port))
        elif raw_ports.startswith("!["):
            list_of_ports = self.__parse_port(raw_ports[1:])
            for port in list_of_ports:
                parsed_ports.append((port[0], bool(~(False ^ port[1])+2))) #xnor
            return parsed_ports
        else:
            parsed_ports = self.__parse_port(raw_ports)
        return parsed_ports   



    # Parses a raw port 
    def __parse_port(self, raw_port):
        if raw_port.startswith("$"):
            return self.ports[raw_port.replace('$', '')]
        elif raw_port.startswith("!$"):
            list_of_ports = self.ports[raw_port.replace("!$", '')]
            parsed_ports = []
            for port in list_of_ports:
                parsed_ports.append((port[0], bool(~(False ^ port[1])+2)))
            return parsed_ports
        elif ":" in raw_port:
            range_ = raw_port.split(":")
            if range_[1] == "":
                return[(range(int(range_[0]), self.MAX_PORT), True)]
            
            lower_bound = int(range_[0]) if int(range_[0]) > self.MIN_PORT else self.MIN_PORT
            upper_bound = int(range_[1]) if int(range_[1]) > self.MIN_PORT else self.MIN_PORT
            return [(range(lower_bound, upper_bound), True)]
        else:
            bool_multiplier = True
            if(raw_port.startswith("!")):
                raw_port = raw_port[1:]
                bool_multiplier = False
            return [(raw_port, bool_multiplier)]



    # Reads line by line and parses lines containing classification priority
    def __parse_classification_priority(self, priority_classification_file):    
        with open(priority_classification_file, 'r') as class_file:
            lines  = class_file.readlines()
            for line in lines:
                if not line.startswith("config classification:"):
                    continue

                class_info = line.replace("config classification: ", "").split(',') # shortname,short_description,priority
                self.classification_priority[class_info[0]] = int(class_info[2])
            

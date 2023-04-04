### This file contains a class that parsers the network variables defined by snort
##  Works for Snort 2.* configuration (future versions will inlcude Snort 3.* and SUricata)

import re
#from compiler.snort_rule_parser.option_validation_dicts import Dicts

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
           

    ### TODO parse with more than 1 sub list in the same level i.e [[], [[], []]]. Needed?
    ### TODO validate input line
    def __parse_ips(self, raw_ips):
        if raw_ips == "any":
            return {"0.0.0.0/0": True}
        elif raw_ips == "!any":
            raise Exception("Invalid IP %s" % raw_ips)
        
        if re.search(r",|(!?\[.*\])", raw_ips):
            parsed_ips = self.__flatten_list(raw_ips, self.__parse_ip)
        else:
            parsed_ips = self.__parse_ip(raw_ips, True)

        return parsed_ips   

    def __flatten_list(self, _list, individual_parser):
        list_deny = True
        if _list.startswith("!"):
            list_deny = False
            _list = _list.lstrip("!")
        _list = re.sub(r'^\[|\]$', '', _list)
        _list = re.sub(r'"', '', _list)
    
        return_list = {}
        if re.search(r"(\[.*\])", _list): # If there is(are) a sub-list(s) process it(them)
            nested_lists = re.split(r",(!?\[.*\])", _list)
            nested_lists = filter(None, nested_lists)
            for _lists in nested_lists: 
                if re.match(r"^\[|^!\[", _lists): # If there are more sub-lists in lower levels process them # match is just the first one 
                    flattened_lists = self.__flatten_list(_lists, self.__parse_ip)
                    for key, value in flattened_lists.items():
                        return_list[key] = bool(~(value ^ list_deny)+2)
                else:
                    for element in _lists.split(","):
                        return_list.update(individual_parser(element, list_deny))
        else:
            for element in _list.split(","):
                return_list.update(individual_parser(element, list_deny))

        return return_list

    # Parses individual IPs. 
    # Obs: Variable inputs (e.g. $HOME_NET) even if they are a list, they are already parsed lists with no sublists and other vars. 
    def __parse_ip(self, raw_ip, parent_bool):
        local_bool = True
        if raw_ip.startswith("!"):
            raw_ip = raw_ip[1:]
            local_bool = False
        if re.match(r'^!?\$', raw_ip):
            ips = self.ip_addresses[re.sub(r'^!?\$', '', raw_ip)]
            return_ips = {}
            bool_multiplier = bool(~(local_bool ^ parent_bool)+2)
            for key, value in ips.items():
                return_ips[key] = bool(~(bool_multiplier ^ value)+2)  #xnor because !! = true
            return return_ips
        
        return {raw_ip: bool(~(local_bool ^ parent_bool)+2)}



    def __parse_ports(self, raw_ports):
        if raw_ports == "any":
            return {range(self.MIN_PORT, self.MAX_PORT): True}
        elif raw_ports == "!any":
            raise Exception("Invalid ports")
        
        if re.search(r",|(!?\[.*\])", raw_ports):
            parsed_ports = self.__flatten_list(raw_ports, self.__parse_port)
        else:
            parsed_ports = self.__parse_port(raw_ports, True)

        return parsed_ports   



    # Parses a raw port 
    def __parse_port(self, raw_port, parent_bool):
        local_bool = True
        if raw_port.startswith("!"):
            raw_port = raw_port[1:]
            local_bool = False

        if re.match(r'^!?\$', raw_port):
            ports = self.ports[re.sub(r'^!?\$', '', raw_port)]
            return_ports = {}
            bool_multiplier = bool(~(local_bool ^ parent_bool)+2)
            for key, value in ports.items():
                return_ports[key] = bool(~(bool_multiplier ^ value)+2)  #xnor because !! = true
            return return_ports
        elif re.match(r'^(!?[0-9]+:|:[0-9]+)', raw_port):
            range_ = raw_port.split(":")
            if len(range_) != 2 or "!" in range_[1]:
                raise ValueError("Wrong range values")
            
            if range_[1] == "":
                return{str(k): bool(~(local_bool ^ parent_bool)+2) for k in range(int(range_[0]), self.MAX_PORT)}
            elif range_[0] == "":
                return{str(k): bool(~(local_bool ^ parent_bool)+2) for k in range(self.MIN_PORT, int(range_[1]))}
            
            lower_bound = int(range_[0]) if int(range_[0]) > self.MIN_PORT else self.MIN_PORT
            upper_bound = int(range_[1]) if int(range_[1]) > self.MIN_PORT else self.MIN_PORT
            return {str(k): bool(~(local_bool ^ parent_bool)+2) for k in range(lower_bound, upper_bound)}
         
        return {raw_port: bool(~(local_bool ^ parent_bool)+2)}




    # Reads line by line and parses lines containing classification priority
    def __parse_classification_priority(self, priority_classification_file):    
        with open(priority_classification_file, 'r') as class_file:
            lines  = class_file.readlines()
            for line in lines:
                if not line.startswith("config classification:"):
                    continue

                class_info = line.replace("config classification: ", "").split(',') # shortname,short_description,priority
                self.classification_priority[class_info[0]] = int(class_info[2])
            

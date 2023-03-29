import re
import ipaddress
import collections
from typing import Tuple, List, Dict, Any



try:
    from .dicts import Dicts
except ImportError:
    from dicts import Dicts


class Parser(object):

    def __init__(self, rule):
        self.dicts = Dicts()
        self.rule = rule
        self.header = self.parse_header()
        # self.options = self.parse_options() 

        # self.validate_options(self.options)
        # self.data = {"header": self.header, "options": self.options}
        # self.all = self.data
        # self.has_negation = self.compute_negation()


    def __iter__(self):
        yield self.data

    def __getitem__(self, key):
        if key == 'all':
            return self.data
        else:
            return self.data[key]


    def parse_header(self):
        if self.get_header():
            header = self.get_header()

            # Remove whitespaces between list elements
            if re.search(r"[,\[\]]\s", header): 
                header = re.sub(r",\s+", ",", header)
                header = re.sub(r"\s+,", ",", header)
                header = re.sub(r"\[\s+", "[", header)
                header = re.sub(r"\s+\]", "]", header)
            header = header.split()
        else:
            raise ValueError("Header is missing, or unparsable")
        
        header = list(filter(None, header))
        size = len(header)
        if not size == 7 and not size == 1:
            msg = "Snort rule header is malformed %s" % header
            raise ValueError(msg)
        
        return self.header_list_to_dict(header)
    
    # Return string with following format: "action proto src_ip src_port direction dst_ip dst_port"
    def get_header(self):
        if re.match(r'(^[a-z|A-Z].+?)?(\(.+;\)|;\s\))', self.rule.lstrip()): #simplify
            header = self.rule.split('(', 1)
            return header[0]
        else:
            msg = 'Error in syntax, check if rule'\
                  'has been closed properly %s ' % self.rule
            raise SyntaxError(msg)

        
    def header_list_to_dict(self, header):
        header_dict = collections.OrderedDict()
        for item in header:
            if "action" not in header_dict:
                header_dict["action"] = self.actions(item)
                continue

            if "proto" not in header_dict:
                header_dict["proto"] = self.proto(item)
                continue
               
            if "source" not in header_dict:
                header_dict["source"] = self.ip(item)
                continue
                
            if "src_port" not in header_dict:
                header_dict["src_port"] = self.port(item)
                print(header_dict["src_port"])
                continue

            if "direction" not in header_dict:
                header_dict["direction"] = self.direction(item)
                continue

            if "destination" not in header_dict:
                header_dict["destination"] = self.ip(item)
                continue

            if "dst_port" not in header_dict:
                header_dict["dst_port"] = self.port(item)
                continue

        print(header_dict)

        return header_dict

    @staticmethod
    def actions(action: str) -> str:
        actions = {
            "alert",
            "log",
            "pass",
            "activate",
            "dynamic",
            "drop",
            "reject",
            "sdrop"
        }

        if action in actions:
            return action
        else:
            msg = "Invalid action specified %s" % action
            raise ValueError(msg)

    @staticmethod
    def proto(proto: str) -> str:
        protos = {
            "tcp",
            "udp",
            "icmp",
            "ip"
        }

        if proto.lower() in protos:
            return proto
        else:
            msg = "Unsupported Protocol %s " % proto
            raise ValueError(msg)

    # Parses IP input
    def ip(self, ip):
        if isinstance(ip, str):
            ip = ip.strip('"')
            if re.search(r",", ip):
                item = self.__flatten_ip(ip)
                ip = item
            else:
                ip = self.__ip_to_tuple(ip)

            if self.__validate_ip(ip):
                return ip
            else:
                raise ValueError("Unvalid ip or variable: %s" % ip)
            
    # Flattens a list of ip or ip-placeholder that might contains a sub-list.
    # If the sub-list has a sub-list this process is repeated until no sub-lists exists
    # Does not work for two sub-lists on the same level
    def __flatten_ip(self, ip):
        list_deny = True
        if ip.startswith("!"):
            list_deny = False
            ip = ip.lstrip("!")
        _ip_list = []
        _not_nest = True
        ip = re.sub(r'^\[|\]$', '', ip)
        ip = re.sub(r'"', '', ip)
        if re.search(r"(\[.*\])", ip): # If there is(are) a sub-list(s) process it(them)
            _not_nest = False
            nest = re.split(r",(!?\[.*\])", ip)
            nest = filter(None, nest)
            _return_ips = []
            for item in nest: 
                if re.match(r"^\[|^!\[", item): # If there are more sub-lists in lower levels process them
                    nested = self.__flatten_ip(item)
                    _return_ips.append(nested)
                    continue
                else:
                    _ip_list = self. __form_ip_list(item)
                    for _ip in _ip_list:
                        _return_ips.append(_ip)
            return list_deny, _return_ips
        if _not_nest:
            _ip_list = self. __form_ip_list(ip)
            return list_deny, _ip_list
        
    # Returns a tuple (Bool, IP) indicating if the IP is negated
    @staticmethod
    def __ip_to_tuple(ip: str) -> Tuple:
        if ip.startswith("!"):
            ip = ip.lstrip("!")
            return False, ip
        else:
            return True, ip
        
    # Tranforms a string of IPs separated by "," into a list
    def __form_ip_list(self, ip_list: str) -> List:
        return [self.__ip_to_tuple(ip) for ip in ip_list.split(",")]


    # Validate if the IP is either a OS variable (e.g. $HOME_NET) or a valid IPv4 or IPv6 address
    def __validate_ip(self, ips):
        variables = {
            "$EXTERNAL_NET",
            "$HTTP_SERVERS",
            "$INTERNAL_NET",
            "$SQL_SERVERS",
            "$SMTP_SERVERS",
            "$DNS_SERVERS",
            "$TELNET_SERVERS",
            "$AIM_SERVERS",
            "$SIP_SERVERS",
            "$HOME_NET",
            "HOME_NET",
            "any"
        }
        for item in ips:
            if isinstance(item, bool):
                pass

            if isinstance(item, list):
                for ip in item:
                    self.__validate_ip(ip)

            if isinstance(item, str):
                if item not in variables:
                    ip_network = item.replace('[', '').replace(']', '')
                    if "/" in item:
                        ipaddress.ip_network(ip_network, False)
                    else:
                        ipaddress.ip_address(ip_network)
        return True
    

    def port(self, port):
        if isinstance(port, str):
            port = port.strip('"')
            if re.search(r"\[", port):
                item = self.__flatten_port(port)
                port = item
            else:
                port = self.__port_to_tuple(port)

            if self.__validate_port(port):
                return port
            else:
                raise ValueError("Unvalid port or variable: %s" % port)

    def __flatten_port(self, port):
        list_deny = True
        if port.startswith("!"):
            list_deny = False
            port = port.lstrip("!")
        _port_list = []
        _not_nest = True
        port = re.sub(r'^\[|\]$', '', port)
        port = re.sub(r'"', '', port)
        if re.search(r"(\[.*\])", port): # If there is(are) a sub-list(s) process it(them)
            _not_nest = False
            nest = re.split(r",(!?\[.*\])", port)
            nest = filter(None, nest)
            _return_ports = []
            for item in nest: 
                if re.match(r"^\[|^!\[", item): # If there are more sub-lists in lower levels process them
                    nested = self.__flatten_port(item)
                    _return_ports.append(nested)
                    continue
                else:
                    _port_list = self. __form_port_list(item)
                    for _port in _port_list:
                        _return_ports.append(_port)
            return list_deny, _return_ports
        if _not_nest:
            _port_list = self. __form_port_list(port)
            return list_deny, _port_list

    @staticmethod
    def __port_to_tuple(port: str) -> Tuple:
        if re.search(r':.*!|!.*:', port):
            raise Exception("Range with negation")
        
        if port.startswith("!"):
            port = port.lstrip("!")
            return False, port
        else:
            return True, port
        
    def __form_port_list(self, port_list: str) -> List:
        return [self.__port_to_tuple(port) for port in port_list.split(",")]
        
    def __validate_port(self, ports):
        variables = {"any", "$HTTP_PORTS"}
        for item in ports:
            if isinstance(item, bool):
                pass

            if isinstance(item, list):
                for port_list_item in item:
                    self.__validate_port(port_list_item)

            if isinstance(item, str):
                if item not in variables and not re.search(r"^\$+", item):
                    if re.search(":", item):
                        range_elements = item.split(":", 1)
                        open_range = False
                        for element in range_elements:
                            if not element:
                                open_range = True
                                continue
                            if element in variables or re.search(r"^\$+", element):
                                continue
                            
                            if int(element) < 0 or int(element) > 65535:
                                raise ValueError("Port is out of range %s" % element)
                        if(not open_range):
                            if(int(range_elements[0]) > int(range_elements[-1])):
                                raise ValueError("Port range is malformed %s" % item)
                    elif int(item) < 0 or int(item) > 65535:
                        raise ValueError("Port is out of range %s" % item)
        return True
        
        
    def direction(self, dst):
        destinations = {"->": "unidirectional",
                        "<>": "bidirectional"}

        if dst in destinations:
            return destinations[dst]
        else:
            msg = "Invalid destination variable %s" % dst
            raise ValueError(msg)
        

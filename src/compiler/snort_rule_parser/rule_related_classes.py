import attr


### Class representing a rule.
class Rule(object):
    def __init__(self, rule, header, options, has_negation):
        self.rule = rule

        self.header = header
        self.options = options
        self.has_negation = has_negation

        self.data = {"header": self.header, "options": self.options}
        self.all = self.data

    def rule_id(self):
        id = ""
        for key, value in self.header.items():
            id+=str(value)

        flags = self.options.get("flags", [])
        if flags:
            flags = flags[1][0]

        return id+str(flags)
    

    def __getitem__(self, key):
        if key == 'all':
            return self.data
        else:
            return self.data[key]
        


# Class that aggreggates multiple rule with the same header values and tcp flag options
class AggregatedRule(object):
    def __init__(self, header={}, flags=str(), priority_list=[], sid_rev_list=[]):
        self.header = header
        self.flags = flags

        self.priority_list = priority_list
        self.sid_rev_list = sid_rev_list

    def rules_count(self):
        return len(self.priority_list)

    def min_priority(self):
        return min(self.priority_list)

    def max_priority(self):
        return max(self.priority_list)

    def sids(self):
        return list(set(self.sid_list))
    
    # def to_match_string(self):
    #     src_port_string = self.__port_to_P4_match(self.src_port)
    #     dst_port_string = self.__port_to_P4_match(self.dst_port)

    #     return f'{hex(self.proto)} ' + \
    #            f'0x{self.src_addr.decode("utf-8")}&&&0x{self.src_addr_mask.decode("utf-8")} ' + \
    #            src_port_string + \
    #            f'0x{self.dst_addr.decode("utf-8")}&&&0x{self.dst_addr_mask.decode("utf-8")} ' + \
    #            dst_port_string + \
    #            f'{hex(self.flags)}&&&{hex(self.flags_mask)}'

    # @staticmethod
    # def __port_to_P4_match(port):
    #     port_to_string = ""
    #     if(isinstance(port, range)):
    #         port_to_string = f'{port.start}->{port.stop}'
    #     else:
    #         port_to_string = f'{port} '

    #     return port_to_string

    # def to_dict(self):
    #     return {'match': self.to_match_string(),
    #             'priority_list': self.priority_list,
    #             'sid_list': self.sid_list}
    
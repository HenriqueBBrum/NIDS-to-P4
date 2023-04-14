### File containing P4 related class to change it from Snort Rules to P4 table actions

import attr

@attr.s
class P4CompiledMatchRule(object):
    proto = attr.ib(default=0, order=False)

    #header_value_bool = attr.ib(default={"src_addr": True, "src_port": True, "dst_addr": True, "dst_port": True}, order=False)

    src_network = attr.ib(default=str(), order=False)
    src_port = attr.ib(default=str(), order=False)


    dst_network = attr.ib(default=str(), order=False)
    dst_port = attr.ib(default=str(), order=False)

    flags = attr.ib(default=0xff, order=False)
    flags_mask = attr.ib(default=0xff, order=False)

    def to_string(self):
        src_port_string = self.__port_to_P4_match(self.src_port)
        dst_port_string = self.__port_to_P4_match(self.dst_port)

        return f'{hex(self.proto)} ' + \
               self.src_network[0] + " " + \
               src_port_string + \
               self.dst_network[0] + " " + \
               dst_port_string + \
               f'{hex(self.flags)}&&&{hex(self.flags_mask)}'

    @staticmethod
    def __port_to_P4_match(port):
        port_to_string = ""
        if(isinstance(port, range)):
            port_to_string = f'{port.start}->{port.stop} '
        else:
            port_to_string = f'{port} '

        return port_to_string

@attr.s
class P4MatchAggregatedRule(object):
    match = attr.ib(default=P4CompiledMatchRule(), order=False)
    priority_list = attr.ib(default=[], order=False)
    sid_rev_list = attr.ib(default=[], order=False)

    def rules_count(self):
        return len(self.priority_list)

    def min_priority(self):
        return min(self.priority_list)

    def max_priority(self):
        return max(self.priority_list)

    def sids(self):
        return list(set(self.sid_list))

    def to_dict(self):
        return {'match': self.match.to_match_string(),
                'priority_list': self.priority_list,
                'sid_list': self.sid_list}

@attr.s
class P4CompiledRule(object):
    table = attr.ib(default=str(), order=False)
    match = attr.ib(default=P4CompiledMatchRule(), order=False)
    action = attr.ib(default=str(), order=False)
    params = attr.ib(default=[], order=False)
    priority = attr.ib(default=str(), order=False)

    def to_rule_string(self):
        params = self.params if self.params and type(self.params) == list else []
        parsed_params = " ".join(params)
        return f'table_add {self.table} {self.action} {self.match.to_match_string()} => {parsed_params} {self.priority}'


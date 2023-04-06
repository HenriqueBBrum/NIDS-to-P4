### File containing P4 related class to change it from Snort Rules to P4 table actions

import attr

@attr.s
class P4CompiledMatchRule(object):
    proto = attr.ib(default=0, order=False)

    src_network = attr.ib(default=str(), order=False)
    src_addr = attr.ib(default=str(), order=False)
    src_addr_mask = attr.ib(default=str(), order=False)

    src_port_start = attr.ib(default=str(), order=False)
    src_port_end = attr.ib(default=str(), order=False)

    dst_network = attr.ib(default=str(), order=False)
    dst_addr = attr.ib(default=str(), order=False)
    dst_addr_mask = attr.ib(default=str(), order=False)

    dst_port_start = attr.ib(default=str(), order=False)
    dst_port_end = attr.ib(default=str(), order=False)

    flags = attr.ib(default=0xff, order=False)
    flags_mask = attr.ib(default=0xff, order=False)

    def to_match_string(self,):
        src_port_start = self.src_port_start
        src_port_end = self.src_port_end
        dst_port_start = self.dst_port_start
        dst_port_end = self.dst_port_end
        if src_port_start == -1:
            src_port_start = 0x0
        if src_port_end == -1:
            src_port_end = 0xffff
        if dst_port_start == -1:
            dst_port_start = 0x0
        if dst_port_end == -1:
            dst_port_end = 0xffff

        return f'{hex(self.proto)} ' + \
               f'0x{self.src_addr.decode("utf-8")}&&&0x{self.src_addr_mask.decode("utf-8")} ' + \
               f'{src_port_start}->{src_port_end} ' + \
               f'0x{self.dst_addr.decode("utf-8")}&&&0x{self.dst_addr_mask.decode("utf-8")} ' + \
               f'{dst_port_start}->{dst_port_end} ' + \
               f'{hex(self.flags)}&&&{hex(self.flags_mask)}'

@attr.s
class P4CompiledIDSMatchRule(object):
    match = attr.ib(default=P4CompiledMatchRule(), order=False)
    priority = attr.ib(default=-1, order=False)
    sid = attr.ib(default=[], order=False)
    rev = attr.ib(default=[], order=False)

    def to_sid_rev_string(self):
        return f'{self.sid}/{self.rev}'

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

@attr.s
class P4MatchAggregatedRule(object):
    match = attr.ib(default=P4CompiledMatchRule(), order=False)
    priority_list = attr.ib(default=[], order=False)
    sid_list = attr.ib(default=[], order=False)

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

# @attr.s
# class P4Rule(object):
#     action = attr.ib(default=str(), order=False)
#     proto = attr.ib(default=0, order=False)
#     src_addr = attr.ib(default=str(), order=False)
#     src_port = attr.ib(default=str(), order=False)
#     dst_addr = attr.ib(default=str(), order=False)
#     dst_port = attr.ib(default=str(), order=False)
#     priority = attr.ib(default=str(), order=False)

# @attr.s
# class AggregatedP4Rule(object):
#     p4_rule = attr.ib(default=P4Rule(), order=False)
#     min_priority = attr.ib(default=0, order=False)
#     max_priority = attr.ib(default=0, order=False)
#     srids = attr.ib(default=[], order=False)

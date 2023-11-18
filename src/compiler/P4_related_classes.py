### File containing P4 related classes to change it from Snort Rules to P4 table entries

import attr

# P4Match is the match fields used to pre-filter traffic in the data plane. 
# These fields are protocol, src IP and port, dst IP and port, and TCP flags (if TCP is used)
@attr.s
class P4Match(object):
    proto = attr.ib(default=0, order=False)

    src_network = attr.ib(default=str(), order=False)
    src_addr = attr.ib(default=str(), order=False)
    src_addr_mask = attr.ib(default=str(), order=False)

    src_port = attr.ib(default=str(), order=False)

    dst_network = attr.ib(default=str(), order=False)
    dst_addr = attr.ib(default=str(), order=False)
    dst_addr_mask = attr.ib(default=str(), order=False)

    dst_port = attr.ib(default=str(), order=False)

    flags = attr.ib(default=str(), order=False)

    def to_string(self):
        src_port_string = self.__port_to_P4_match(self.src_port)
        dst_port_string = self.__port_to_P4_match(self.dst_port)

        return f'{hex(self.proto)} ' + \
               f'{self.src_addr}&&&{self.src_addr_mask} ' + \
               src_port_string + \
               f'{self.dst_addr}&&&{self.dst_addr_mask} ' + \
               dst_port_string + \
               f'{self.flags}'

    @staticmethod
    def __port_to_P4_match(port):
        port_to_string = ""
        if(isinstance(port, range)):
            port_to_string = f'{port.start}->{port.stop-1} '
        else:
            port_to_string = f'{port}->{port} '

        return port_to_string

# P4AggregatedMatch stores the sids and priority information of repeated table entry matches or matches that were "groupped"
@attr.s
class P4AggregatedMatch(object):
    match = attr.ib(default=P4Match(), order=False)
    priority_list = attr.ib(default=[], order=False) # SNORT PRIORITY: SMALLER NUMBERS HIGHER PRIORIRTY
    sid_rev_list = attr.ib(default=[], order=False)

    def match_count(self):
        return len(self.priority_list)

    # Smaller numbers indicate higher severity
    def min_priority(self):
        return min(self.priority_list)

    def max_priority(self):
        return max(self.priority_list)

    def sid_rev(self):
        return list(set(self.sid_rev_list))
        
# P4TableEntry is the final object representing the P4 table entries
@attr.s
class P4TableEntry(object):
    table = attr.ib(default=str(), order=False)
    agg_match = attr.ib(default=P4AggregatedMatch(), order=False)
    action = attr.ib(default=str(), order=False)
    params = attr.ib(default=[], order=False)
    priority = attr.ib(default=str(), order=False) # P4 TABLE PRIORITY: BIGGER NUMBERS HIGHER PRIORIRTY

    def to_string(self):
        params = self.params if self.params and type(self.params) == list else []
        parsed_params = " ".join(params)
        if not params: 
            return f'table_add {self.table} {self.action} {self.agg_match.match.to_string()} => {self.priority}'

        return f'table_add {self.table} {self.action} {self.agg_match.match.to_string()} => {parsed_params} {self.priority}'



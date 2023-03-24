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




    def parse_header(self):
        if self.get_header():
            header = self.get_header()

            # Remove 
            if re.search(r"[,\[\]]\s", header): 
                header = re.sub(r",\s+", ",", header)
                header = re.sub(r"\s+,", ",", header)
                header = re.sub(r"\[\s+", "[", header)
                header = re.sub(r"\s+\]", "]", header)
                print(header)
            header = header.split()
        else:
            raise ValueError("Header is missing, or unparsable")



    def get_header(self):
        if re.match(r'(^[a-z|A-Z].+?)?(\(.+;\)|;\s\))', self.rule.lstrip()): #simplify
            header = self.rule.split('(', 1)
            return header[0]
        else:
            msg = 'Error in syntax, check if rule'\
                  'has been closed properly %s ' % self.rule
            raise SyntaxError(msg)

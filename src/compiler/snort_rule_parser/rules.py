


class Rule():
    def __init__(self, rule):
        self.rule = rule

        self.action = ""
        self.proto = ""
        self.direction = ""
        self.src = ()
        self.dst = ()

        self.options = {}

    # def __str__():
        
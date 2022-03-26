import pprint


class OperatorType(object):
    def __init__(self, parent):
        self.parent = parent

    # def __repr__(self):
    #     ipmatch = ""
    #     repr = ""
    #     if self.ipmatch:
    #         ipmatch = self.ipmatch
    #     repr = "{ipmatch}".format(
    #         ipmatch=ipmatch
    #     )
    #     return repr


class Operator(object):
    def __init__(self, parent, negated, name, value):
        self.parent = parent
        self.negated = negated
        self.name = name
        self.value = value
        pp = pprint.PrettyPrinter(indent=4, depth=10)
        pp.pprint(name)
        pp.pprint(value)

    def __repr__(self):
        name = ""
        value = ""
        negated = ""
        if self.name:
            name = self.name
        if self.value:
            value = self.value
        if self.negated:
            negated = "!"

        repr = "{negated}@{name} {value}".format(negated=negated, name=name, value=value)
        return repr

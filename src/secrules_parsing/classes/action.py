class Action(object):
    """ """

    def __init__(self, parent, name, value):
        self.parent = parent
        self.name = name
        self.value = value


    def __repr__(self):
        value = ""
        indent = self.parent.actions_indent()
        if self.value is not None:
            value = self.value
        # Don't indent if the action is the first one
        if self.is_first_action():
            indent = ""
        repr = "{indent}{name}{value}".format(
            name=self.name, value=value, indent=indent
        )

        return repr

    def is_first_action(self):
        first = False
        if self.name == "id" or (self.name == "capture" and self.parent.id is None):
            first = True
        return first


class ActionType(object):
    """
        Tag | id=ID | INT | "'"? STRING "'"? | msg=MessageValue |
    CollectionType | StringWithMacros | transformations*=Transformation[','];
    """

    def __init__(self, parent, transformations):
        self.parent = parent
        self.transformations = transformations

    def __repr__(self):
        # TODO: add transformations
        return ""

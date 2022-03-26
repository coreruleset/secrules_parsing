class Collection(object):
    """
    count=CountCollectionOperator? collection=CollectionName ':'? collectionArg=CollectionArgument?;
    """

    def __init__(self, parent, count, name, arg):
        self.parent = parent
        self.count = count
        self.name = name
        self.arg = arg

    def __repr__(self):
        count = ""
        name = ""
        arg = ""
        if self.count:
            count = "&"
        if self.name:
            name = self.name
        if self.arg:
            arg = self.arg

        repr = "{count}{name}:{arg}".format(count=count, name=name, arg=arg)
        return repr
